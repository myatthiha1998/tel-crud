# coding:utf-8
from google.appengine.ext.ndb.model import StringProperty, TextProperty, BooleanProperty, DateTimeProperty

from endpoint.entity import BaseModel


class TelephoneTemplate(BaseModel):
    name = StringProperty(required=True)
    kind = StringProperty(required=True, indexed=True)
    title = StringProperty(required=True)
    body = TextProperty()
    attachment_url = StringProperty()
    attachment_name = StringProperty()
    enable_resend_tel = BooleanProperty(required=True, default=True, indexed=True)
    KIND_BOOT_NOTICE = "boot_notice"
    KIND_ANSWER_REQUEST = "answer_request"
    KINDS = [KIND_BOOT_NOTICE, KIND_ANSWER_REQUEST]
    register_datetime = DateTimeProperty(auto_now_add=True, indexed=True)
    update_datetime = DateTimeProperty(auto_now=True, indexed=True)
