export function extractComponentOfWebId(webId, part) {
    let result;
    switch (part) {
      case 0:
        result = webId.substring(0, webId.indexOf(".com/") + 5);
        break;
      case 1:
        result = webId.substring(
          webId.indexOf(".com/") + 5,
          webId.indexOf("/profile/")
        );
        break;
      case 2:
        result = webId.substring(webId.indexOf("/profile/"));
        break;
    }
    return result;
}

export function identityProviderConfigUrl(url) {
  return `${url}${
    url.endsWith("/") ? "" : "/"
  }.well-known/openid-configuration`;
}