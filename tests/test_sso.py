import unittest

from bs4 import BeautifulSoup

from ipgw.core.api.SSO import SSO_login, SSO_prepare, _js_length, _login_target
from ipgw.core.api.SSO_error import BackendError, UnionAuthError
from ipgw.core.api.sso_rsa import extract_login_page_rsa_public_key

PUBLIC_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAim8qD5MR43u+GUY3HCg4kL7f6nU2AkmibtwB15iShZ2iYuy4fkC7U8YoSSVmvnxGYGMTK/X0X6AFBzOqA1c87h/gN9mSaavyBXB3rYBbtdEAukleXj+hW44WsZu8QGYZBfPvH6N2/vwvzqTB6YWN6xWOyFvwN/D1fsfECjtL1r7q4kzvemZp729nO7Vc0HSpIH5b7n5SiXW52PZ3RO708GAJBd6UDGGxF6I66ugczR9URdkE6IeU1W5vu7H+KDvz+CMFzsZao9sWyErDYKsXLjVM5EDx4bvIJse8FbKLkow5Lc3oFcxisbll68txMcg1o5EX9Zvo8e7L4ki7hwdA3wIDAQAB"
)


class FakeResponse:
    def __init__(self, text, status_code=200, url=""):
        self.text = text
        self.status_code = status_code
        self.url = url


class FakeSession:
    def __init__(self, responses=None, post_response=None):
        self.responses = responses or {}
        self.post_response = post_response
        self.requests = []
        self.posts = []

    def get(self, url, **kwargs):
        self.requests.append(url)
        if url not in self.responses:
            raise AssertionError("unexpected GET " + url)
        return self.responses[url]

    def post(self, url, data=None, allow_redirects=True, **kwargs):
        self.posts.append((url, data, allow_redirects))
        return self.post_response


def inline_page(key=PUBLIC_KEY):
    return '<html><head><title>智慧东大--统一身份认证</title><script>var publicKeyStr = "' + key + '";</script></head></html>'


def form_page(action="/tpass/login?service=fixture", script_src=None):
    script = '<script src="' + script_src + '"></script>' if script_src else '<script>var publicKeyStr = "' + PUBLIC_KEY + '";</script>'
    return (
        '<html><head><title>智慧东大--统一身份认证</title>' + script + '</head><body>'
        '<form id="loginForm" action="' + action + '">'
        '<input name="lt" value="LT-fixture"/>'
        '<input name="execution" value="e1s1"/>'
        '<input id="rsa" name="enc"/>'
        '<input id="ul" name="ulen"/>'
        '<input id="pl" name="plen"/>'
        '</form></body></html>'
    )


class KeyDiscoveryTests(unittest.TestCase):
    def test_inline_key_is_used_without_a_request(self):
        session = FakeSession()
        soup = BeautifulSoup(inline_page(), "html.parser")
        self.assertEqual(extract_login_page_rsa_public_key(session, soup), PUBLIC_KEY)
        self.assertEqual(session.requests, [])

    def test_renamed_script_falls_back_to_a_working_candidate(self):
        html = (
            '<script src="/tpass/comm/js/jquery.min.js"></script>'
            '<script src="/tpass/comm/neu/js/rsa.js"></script>'
            '<script src="/tpass/comm/neu/js/login_neu_new.js?v=3"></script>'
            '<script src="/tpass/comm/neu/js/login_keys.js"></script>'
        )
        first = "https://pass.neu.edu.cn/tpass/comm/neu/js/login_neu_new.js?v=3"
        second = "https://pass.neu.edu.cn/tpass/comm/neu/js/login_keys.js"
        session = FakeSession(
            {
                first: FakeResponse("var other = 1;"),
                second: FakeResponse('var publicKeyStr = "' + PUBLIC_KEY + '";'),
            }
        )
        self.assertEqual(
            extract_login_page_rsa_public_key(session, BeautifulSoup(html, "html.parser")),
            PUBLIC_KEY,
        )
        self.assertEqual(session.requests, [first, second])

    def test_cross_origin_login_script_is_rejected(self):
        html = '<script src="http://pass.neu.edu.cn/login_neu_new.js"></script>'
        session = FakeSession()
        with self.assertRaises(BackendError):
            extract_login_page_rsa_public_key(session, BeautifulSoup(html, "html.parser"))
        self.assertEqual(session.requests, [])

    def test_missing_key_reports_candidates(self):
        html = '<html><title>fixture</title><script src="/login_neu_new.js"></script></html>'
        session = FakeSession({"https://pass.neu.edu.cn/login_neu_new.js": FakeResponse("var other = 1;")})
        with self.assertRaises(BackendError) as raised:
            extract_login_page_rsa_public_key(session, BeautifulSoup(html, "html.parser"))
        self.assertIn("login_neu_new.js", str(raised.exception))


class FormTests(unittest.TestCase):
    def test_fields_and_destination_are_discovered(self):
        ac_id = 16
        login_url = _login_target(ac_id)
        session = FakeSession({login_url: FakeResponse(form_page())})
        page = SSO_prepare(session, ac_id)
        self.assertEqual(page["rsa_field"], "enc")
        self.assertEqual(page["ul_field"], "ulen")
        self.assertEqual(page["pl_field"], "plen")
        self.assertEqual(page["form_lt_string"], "LT-fixture")
        self.assertEqual(page["form_execution"], "e1s1")
        self.assertEqual(page["form_destination"], "https://pass.neu.edu.cn/tpass/login?service=fixture")

    def test_untrusted_action_is_rejected(self):
        login_url = _login_target(16)
        session = FakeSession({login_url: FakeResponse(form_page(action="https://evil.example/login"))})
        with self.assertRaises(BackendError):
            SSO_prepare(session, 16)

    def test_login_uses_discovered_names_and_utf16_lengths(self):
        page = {
            "form_lt_string": "LT-fixture",
            "form_execution": "e1s1",
            "form_destination": "https://pass.neu.edu.cn/tpass/login?service=fixture",
            "rsa_public_key": PUBLIC_KEY,
            "rsa_field": "enc",
            "ul_field": "ulen",
            "pl_field": "plen",
        }
        result_url = "http://ipgw.neu.edu.cn/srun_portal_sso?ac_id=16&ticket=ST-test"
        session = FakeSession(post_response=FakeResponse("<html><title>IP控制网关</title></html>", url=result_url))
        self.assertEqual(SSO_login(session, page, "u😀", "p", 16), "ST-test")
        posted_url, data, allow_redirects = session.posts[0]
        self.assertEqual(posted_url, page["form_destination"])
        self.assertTrue(allow_redirects)
        self.assertIn("enc", data)
        self.assertNotIn("rsa", data)
        self.assertEqual(data["ulen"], 3)
        self.assertEqual(data["plen"], 1)
        self.assertEqual(data["lt"], "LT-fixture")
        self.assertEqual(data["_eventId"], "submit")

    def test_password_error_is_classified(self):
        page = {
            "form_lt_string": "LT-fixture",
            "form_execution": "e1s1",
            "form_destination": "https://pass.neu.edu.cn/tpass/login?service=fixture",
            "rsa_public_key": PUBLIC_KEY,
            "rsa_field": "rsa",
            "ul_field": "ul",
            "pl_field": "pl",
        }
        session = FakeSession(post_response=FakeResponse("<html><title>智慧东大--统一身份认证</title></html>"))
        with self.assertRaises(UnionAuthError):
            SSO_login(session, page, "u", "p", 16)

    def test_js_length_counts_utf16_units(self):
        self.assertEqual(_js_length("abc"), 3)
        self.assertEqual(_js_length("u😀"), 3)


if __name__ == "__main__":
    unittest.main()
