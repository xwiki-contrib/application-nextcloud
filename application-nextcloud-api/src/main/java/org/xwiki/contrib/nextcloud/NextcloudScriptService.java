/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.xwiki.contrib.nextcloud;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.jose.util.Base64URL;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.XWikiBearerAccessToken;
import org.xwiki.script.service.ScriptService;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;

@Component
@Singleton
@Named("nextcloud")
public class NextcloudScriptService implements ScriptService
{
    private static final List<String> NS = Arrays.asList("Nextcloud");
    private static final String PROP_CODES = "codes";
    private static final String PROP_URL = "url";
    private static final String PROP_REDIRECT_URI = "redirectUri";
    private static final String PROP_CLIENT_ID = "clientId";

    /** Location of the class representing a Nextcloud Instance. */
    public static final LocalDocumentReference NEXTCLOUD_INSTANCE_CLASS =
        new LocalDocumentReference(NS, "InstanceClass");

    /** Location of the configuration document. */
    public static final LocalDocumentReference NEXTCLOUD_CONFIG_REFERENCE =
        new LocalDocumentReference(NS, "Configuration");

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private OIDCStore store;

    @Inject
    @Named("currentmixed")
    private DocumentReferenceResolver<String> documentReferenceResolver;

    /**
     * @return a new token for the given Nextcloud instance.
     * @param clientId the client ID of the Nextcloud instance
     * @param redirectUri the redirect uri of the Nextcloud instance
     * @param userReferenceString the reference of the user for which the token is created
     * @throws URISyntaxException when the given redirectUri is malformed
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public String createNewToken(String clientId, String userReferenceString, String redirectUri)
        throws URISyntaxException, XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();
        XWiki wiki = xcontext.getWiki();
        DocumentReference userDocumentReference = documentReferenceResolver.resolve(userReferenceString);
        XWikiDocument userDocument = wiki.getDocument(userDocumentReference, xcontext);
        if (userDocument.isNew()) {
            return null;
        }
        int xobjectNumber = userDocument.createXObject(OIDCConsent.REFERENCE, xcontext);
        OIDCConsent consent = new OIDCConsent(userDocument.getXObject(OIDCConsent.REFERENCE, xobjectNumber));
        consent.setClientID(new ClientID(clientId));
        consent.setRedirectURI(new URI(redirectUri));
        XWikiBearerAccessToken accessToken = XWikiBearerAccessToken.create(userReferenceString);
        String random = accessToken.getRandom();
        consent.setAccessToken(random, xcontext);
        consent.setAllowed(true);
        store.saveConsent(consent, "Add new OIDC consent for a Nextcloud instance");
        return consent.getReference().toString().replace("Object ", "") + "/" + random;
    }

    /**
     * Remove a client id.
     * @param clientId the client ID of the Nextcloud instance to remove
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public void removeClientId(String clientId)
        throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();
        XWiki wiki = xcontext.getWiki();
        XWikiDocument configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE, xcontext);
        for (BaseObject obj : configDoc.getXObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj != null && clientId.equals(obj.getStringValue(PROP_CLIENT_ID))) {
                String url = obj.getStringValue(PROP_URL);
                configDoc.removeXObject(obj);
                wiki.saveDocument(configDoc, "Removed instance " + url, xcontext);
            }
        }
    }

    /**
     * @return a new client id for the given Nextcloud instance.
     * @param instanceURL the URL of the Nextcloud instance
     * @param redirectUri the redirect uri of the Nextcloud instance
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public String generateClientId(String instanceURL, String redirectUri)
        throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();
        XWiki wiki = xcontext.getWiki();
        XWikiDocument configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE, xcontext);
        byte[] n = new byte[32];
        new SecureRandom().nextBytes(n);
        String clientId = Base64URL.encode(n).toString();

        int objNumber = configDoc.createXObject(NEXTCLOUD_INSTANCE_CLASS, xcontext);
        BaseObject obj = configDoc.getXObject(NEXTCLOUD_INSTANCE_CLASS, objNumber);
        obj.set(PROP_URL, instanceURL, xcontext);
        obj.set(PROP_REDIRECT_URI, redirectUri, xcontext);
        obj.set(PROP_CLIENT_ID, clientId, xcontext);
        wiki.saveDocument(configDoc, "Added instance " + instanceURL, xcontext);
        return clientId;
    }

    /**
     * @return an InstanceClass XObject representing a Nextcloud instance for
     *         the given parameters, or null if it's not found.
     * @param clientId the client ID of the Nextcloud instance
     * @param redirectUri the redirect uri of the Nextcloud instance
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public BaseObject getNextcloudInstanceByClientID(String clientId, String redirectUri)
        throws XWikiException
    {
        if (clientId == null || redirectUri == null) {
            return null;
        }

        XWikiContext xcontext = this.xcontextProvider.get();
        XWiki wiki = xcontext.getWiki();
        XWikiDocument configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE, xcontext);
        for (BaseObject obj : configDoc.getXObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj != null
                && clientId.equals(obj.getStringValue(PROP_CLIENT_ID))
                && redirectUri.equals(obj.getStringValue(PROP_REDIRECT_URI))
            ) {
                return obj;
            }
        }

        return null;
    }

    private Map<String, String> getCodeFromObj(BaseObject obj) throws JsonProcessingException
    {
        String codesStr = obj.getStringValue(PROP_CODES);
        XWikiContext xcontext = this.xcontextProvider.get();
        XWiki wiki = xcontext.getWiki();
        return codesStr.isEmpty()
            ? new HashMap<String, String>()
            : new ObjectMapper().readValue(
                codesStr,
                new TypeReference<Map<String, String>>() { }
            );
    }

    /**
     * Use a grant code.
     * @param code the code to use
     * @param redirectUri the redirectUri of the Nextcloud instance
     * @return a clientId, userReferenceString tuple, or null if the code and
               the redirectUri are not found or don't match
     * @throws XWikiException when it fails to get/set information from the wiki
     * @throws JsonProcessingException when it fails handle the JSON object
                                       where the codes are stored
     */
    public List<String> useCode(String code, String redirectUri)
        throws XWikiException, JsonProcessingException
    {
        if (redirectUri == null) {
            return null;
        }

        XWikiContext xcontext = this.xcontextProvider.get();
        XWiki wiki = xcontext.getWiki();
        XWikiDocument configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE, xcontext);
        ObjectMapper objectMapper = new ObjectMapper();
        for (BaseObject obj : configDoc.getXObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj == null) {
                continue;
            }

            Map<String, String> codes = getCodeFromObj(obj);
            if (codes.containsKey(code)
                && redirectUri.equals(obj.getStringValue(PROP_REDIRECT_URI))
            ) {
                String userReferenceString = codes.get(code);
                String clientId = obj.getStringValue(PROP_CLIENT_ID);
                codes.remove(code);
                obj.set(PROP_CODES, objectMapper.writeValueAsString(codes), xcontext);
                wiki.saveDocument(configDoc, "Removed a code", xcontext);
                return Arrays.asList(clientId, userReferenceString);
            }
        }

        return null;
    }

    /**
     * @return whether a Nextcloud instance is registered
     * @param clientId the client ID of the Nextcloud instance
     * @param redirectUri the redirectUri of the Nextcloud instance
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public boolean isClientIDRegistered(String clientId, String redirectUri)
        throws XWikiException
    {
        return getNextcloudInstanceByClientID(clientId, redirectUri) != null;
    }

    /**
     * @return a new grant code for a Nextcloud instance
     * @param instanceURL the URL of the Nextcloud instance
     * @param redirectUri the redirectUri of the Nextcloud instance
     * @throws XWikiException when it fails to get/set information from the wiki
     * @throws JsonProcessingException when it fails handle the JSON object where the codes are stored
     */
    public String generateGrantCode(String instanceURL, String redirectUri)
        throws XWikiException, JsonProcessingException
    {
        BaseObject obj = getNextcloudInstanceByClientID(instanceURL, redirectUri);
        if (obj != null) {
            XWikiContext xcontext = this.xcontextProvider.get();
            XWiki wiki = xcontext.getWiki();
            byte[] n = new byte[32];
            new SecureRandom().nextBytes(n);
            Map<String, String> codes = getCodeFromObj(obj);
            String code = Base64URL.encode(n).toString();
            codes.put(code, xcontext.getUserReference().toString());
            obj.set(PROP_CODES, new ObjectMapper().writeValueAsString(codes), xcontext);
            XWikiDocument configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE, xcontext);
            wiki.saveDocument(configDoc, "Added code for instance " + instanceURL, xcontext);
            return code;
        }
        return "";
    }
}
