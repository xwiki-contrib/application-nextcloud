# Nextcloud Application

This extension allows users to integrate XWiki with Nextcloud, in XWiki. In
particular, it allows Nextcloud users to login to XWiki from Nextcloud so they
can access their XWiki content from Nextcloud.

* Project Lead: [Raphaël Jakse](https://www.xwiki.org/xwiki/bin/view/XWiki/rjakse)
* [Documentation & Download](https://extensions.xwiki.org/xwiki/bin/view/Extension/Nextcloud+application>)
* [Issue Tracker](https://jira.xwiki.org/browse/NEXTCLOUD)
* Communication: [Forum](https://forum.xwiki.org), [Chat](https://dev.xwiki.org/xwiki/bin/view/Community/Chat)
* [Development Practices](https://contrib.xwiki.org/xwiki/bin/view/Main/WebHome)
* Minimal XWiki version supported: XWiki 11.10
* License: LGPL 2.1
* Translations: N/A
* Sonar Dashboard: N/A
* Continuous Integration Status: N/A

## Requirements

In `xwiki.cfg`, the following setting needs to be set:

```
xwiki.authentication.authclass=org.xwiki.contrib.oidc.provider.OIDCBridgeAuth
```

This authentication class is provided by the
[OpenID Connect Provider](https://extensions.xwiki.org/xwiki/bin/view/Extension/OpenID%20Connect/OpenID%20Connect%20Provider/)
extension that needs to be installed. This class will look for Authentication
HTTP headers and authenticate users using it through OpenID-Connect if it is
present. This is used for authenticating users from Nextcloud.

## XWiki Application for Nextcloud

This XWiki extension is useful with the
[XWiki Nextcloud application](https://github.com/nextcloud/xwiki),
which needs to be installed on the Nextcloud instances you wish to integrate
your wikis with.
