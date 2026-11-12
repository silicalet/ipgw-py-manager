import logging
from typing import TypedDict
from urllib.parse import parse_qs, quote, urljoin, urlparse

from bs4 import BeautifulSoup, Tag
from requests import Session

from .SSO_error import BackendError, UnionAuthError, UnknownPageError
from .sso_rsa import SSO_ORIGIN, extract_login_page_rsa_public_key, rsa_encrypt_username_password

ua = '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'''


def _login_target(ac_id=None) -> str:
    service = "http://ipgw.neu.edu.cn/srun_portal_sso?ac_id=" + str(ac_id if ac_id is not None else 1)
    return SSO_ORIGIN + "/tpass/login?service=" + quote(service, safe="")


target = _login_target(1)


class PageTitle:
    UnionAuth = "智慧东大--统一身份认证"
    SystemHint = "系统提示"
    EmailVerification = "智慧东大"  # 出现这个标题意味着用户需要进行邮箱认证
    IPGWControlGateway = "IP控制网关"


class SSOPage(TypedDict):
    form_lt_string: str
    form_execution: str
    form_destination: str
    rsa_public_key: str
    rsa_field: str
    ul_field: str
    pl_field: str


def _is_cas_url(url: str) -> bool:
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname == "pass.neu.edu.cn" and port in (None, 443)


def _find_form(page_soup: BeautifulSoup) -> Tag:
    form = page_soup.find("form", {"id": "loginForm"})
    if form is not None:
        return form
    for candidate in page_soup.find_all("form"):
        if candidate.find("input", {"id": "rsa"}) or candidate.find("input", {"name": "rsa"}):
            return candidate
    forms = page_soup.find_all("form")
    if len(forms) == 1:
        return forms[0]
    raise BackendError("cannot find SSO login form")


def _find_input(form: Tag, field_id=None, name=None):
    if field_id:
        tag = form.find("input", {"id": field_id})
        if tag is not None:
            return tag
    if name:
        return form.find("input", {"name": name})
    return None


def _require_input(form: Tag, label: str, field_id=None, name=None) -> Tag:
    tag = _find_input(form, field_id=field_id, name=name)
    if tag is None:
        raise BackendError("SSO login form is missing input: " + label)
    return tag


def _input_name(label: str, tag: Tag) -> str:
    name = tag.attrs.get("name", "")
    if not name:
        raise BackendError("SSO login input has no name: " + label)
    return name


def _input_value(label: str, tag: Tag) -> str:
    value = tag.attrs.get("value", "")
    if not value:
        raise BackendError("SSO login input is empty: " + label)
    return value


def _js_length(value: str) -> int:
    # Browser JavaScript string lengths count UTF-16 code units.
    return sum(2 if ord(char) > 0xFFFF else 1 for char in value)


def _ticket_from_url(url: str) -> str:
    tickets = parse_qs(urlparse(url).query).get("ticket")
    if not tickets:
        raise BackendError("SSO login succeeded but the callback URL has no ticket")
    return tickets[0]


# 准备一个SSO内容，里面有
def SSO_prepare(session: Session, ac_id=None) -> SSOPage:
    login_target = _login_target(ac_id)
    page_soup = BeautifulSoup(session.get(login_target).text, "html.parser")
    form = _find_form(page_soup)
    lt_tag = _require_input(form, "lt", field_id="lt", name="lt")
    execution_tag = _require_input(form, "execution", name="execution")
    rsa_tag = _require_input(form, "rsa", field_id="rsa", name="rsa")
    ul_tag = _require_input(form, "ul", field_id="ul", name="ul")
    pl_tag = _require_input(form, "pl", field_id="pl", name="pl")
    action = form.attrs.get("action", "")
    if not action:
        raise BackendError("SSO login form has no action")
    destination = urljoin(login_target, action)
    if not _is_cas_url(destination):
        raise BackendError("SSO login form points to an untrusted origin: " + destination)
    sso_form_data = {
        "form_lt_string": _input_value("lt", lt_tag),
        "form_execution": _input_value("execution", execution_tag),
        "form_destination": destination,
        "rsa_public_key": extract_login_page_rsa_public_key(session, page_soup),
        "rsa_field": _input_name("rsa", rsa_tag),
        "ul_field": _input_name("ul", ul_tag),
        "pl_field": _input_name("pl", pl_tag),
    }
    logging.debug(f"sso_form_data: {sso_form_data}")
    return sso_form_data


# 请求SSO和认证SSO两个操作合并到一个API接口中，直接操作。返回一个SSO ticket。这个函数会触发异常
def SSO_login(session: Session, page: SSOPage, username, password, ac_id) -> str:
    form_data = {
        page["rsa_field"]: rsa_encrypt_username_password(username, password, page["rsa_public_key"]),
        page["ul_field"]: _js_length(username),
        page["pl_field"]: _js_length(password),
        'lt': page['form_lt_string'],
        'execution': page['form_execution'],
        '_eventId': 'submit'
    }
    login_first_result = session.post(page['form_destination'], data=form_data, allow_redirects=True)
    login_first_result_soup = BeautifulSoup(login_first_result.text, "html.parser")
    title_soup = login_first_result_soup.find("title")
    response_page_title = title_soup.get_text(strip=True) if title_soup else ""
    logging.debug("page_title: " + (response_page_title or "<no data>"))
    if not response_page_title:
        # 问题出现！ 这个问题可能是后端返回了一个redis错误的页面
        raise BackendError(login_first_result_soup.text)
    if response_page_title == PageTitle.IPGWControlGateway:
        # 登录成功！
        return _ticket_from_url(login_first_result.url)
    if response_page_title == PageTitle.UnionAuth:
        # 用户名或密码错误
        raise UnionAuthError()
    if response_page_title == PageTitle.EmailVerification:
        # 这个页面可能会出现，因为目标未绑定邮箱。我们这里的处理方法就是简单跳过。
        logging.warning("帐号未绑定邮箱")
        login_skip_email_result = session.get(_login_target(ac_id), allow_redirects=True)
        logging.debug("skip_email")
        return _ticket_from_url(login_skip_email_result.url)
    raise UnknownPageError(login_first_result_soup)
