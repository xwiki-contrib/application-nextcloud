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

package org.xwiki.contrib.nextcloud.internal;

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

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiRightService;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.XWikiBearerAccessToken;
import org.xwiki.script.service.ScriptService;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;

import com.xpn.xwiki.api.Document;
import com.xpn.xwiki.api.Object;
import com.xpn.xwiki.api.XWiki;
import com.xpn.xwiki.XWikiContext;


@Component
@Singleton
@Named("nextcloud")
public class NextcloudInternalScriptService implements ScriptService
{
    /** Location of the configuration document. */
    public static final String NEXTCLOUD_CONFIG_REFERENCE = "Nextcloud.Admin.Configuration";

    /** Location of the class representing a Nextcloud Instance. */
    public static final String NEXTCLOUD_INSTANCE_CLASS = "Nextcloud.InstanceClass";

    private static final String PROP_CODES = "codes";
    private static final String PROP_URL = "url";
    private static final String PROP_REDIRECT_URI = "redirectUri";
    private static final String PROP_CLIENT_ID = "clientId";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private EntityReferenceSerializer<String> serialiser;

    @Inject
    private OIDCStore store;

    @Inject
    @Named("currentmixed")
    private DocumentReferenceResolver<String> documentReferenceResolver;

    /**
     * @return a new token for the given Nextcloud instance.
     * @param clientId the client ID of the Nextcloud instance
     * @param redirectUri the redirect uri of the Nextcloud instance
     * @param user the reference of the user for which the token is created
     * @throws URISyntaxException when the given redirectUri is malformed
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public String createNewToken(String clientId, String user, String redirectUri)
        throws URISyntaxException, XWikiException
    {
        XWikiContext xcontext = xcontextProvider.get();
        DocumentReference userDocumentReference = documentReferenceResolver.resolve(user);
        if (XWikiRightService.isGuest(userDocumentReference)) {
            return null;
        }

        XWiki wiki = new XWiki(xcontext.getWiki(), xcontext);
        Document userDocument = wiki.getDocument(userDocumentReference);
        if (userDocument.isNew()) {
            return null;
        }

        ClientID clientID = new ClientID(clientId);
        URI redirectURI = new URI(redirectUri);

        OIDCConsent consent = store.getConsent(clientID, redirectURI, userDocumentReference);

        if (consent == null) {
            consent = new OIDCConsent(userDocument.getDocument().newXObject(OIDCConsent.REFERENCE, xcontext));
            consent.setClientID(clientID);
            consent.setRedirectURI(redirectURI);
        }
        String consentReference = serialiser.serialize(consent.getReference());
        XWikiBearerAccessToken accessToken = XWikiBearerAccessToken.create(consentReference);
        String random = accessToken.getRandom();
        consent.setAllowed(true);
        consent.setAccessToken(random, xcontext);
        store.saveConsent(consent, "Add OIDC consent for a Nextcloud instance");
        return consentReference.replace("Object ", "") + "/" + random;
    }

    /**
     * Remove a client id.
     * @param clientId the client ID of the Nextcloud instance to remove
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public void removeClientId(String clientId)
        throws XWikiException
    {
        XWikiContext xcontext = xcontextProvider.get();
        XWiki wiki = new XWiki(xcontext.getWiki(), xcontext);
        Document configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE);
        for (Object obj : configDoc.getObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj != null && clientId.equals((String) obj.getValue(PROP_CLIENT_ID))) {
                String url = (String) obj.getValue(PROP_URL);
                configDoc.removeObject(obj);
                configDoc.save("Removed instance " + url);
            }
        }
    }

    /**
     * @return a new client id for the given Nextcloud instance, or null if the
     *         user is not an admin.
     * @param instanceURL the URL of the Nextcloud instance
     * @param redirectUri the redirect uri of the Nextcloud instance
     * @throws XWikiException when it fails to get/set information from the wiki
     */
    public String generateClientId(String instanceURL, String redirectUri)
        throws XWikiException
    {
        XWikiContext xcontext = xcontextProvider.get();
        XWiki wiki = new XWiki(xcontext.getWiki(), xcontext);
        if (!wiki.hasAdminRights()) {
            return null;
        }
        Document configDoc = wiki.getDocument(NEXTCLOUD_CONFIG_REFERENCE);
        byte[] n = new byte[32];
        new SecureRandom().nextBytes(n);
        String clientId = Base64URL.encode(n).toString();

        int objNumber = configDoc.createNewObject(NEXTCLOUD_INSTANCE_CLASS);
        Object obj = configDoc.getObject(NEXTCLOUD_INSTANCE_CLASS, objNumber);
        obj.set(PROP_URL, instanceURL);
        obj.set(PROP_REDIRECT_URI, redirectUri);
        obj.set(PROP_CLIENT_ID, clientId);
        configDoc.save("Added instance " + instanceURL);
        return clientId;
    }

    private Map<String, String> getCodeFromObj(Object obj) throws JsonProcessingException
    {
        String codesStr = (String) obj.getValue(PROP_CODES);
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
     * @return a clientId, user tuple, or null if the code and
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

        XWikiContext xcontext = xcontextProvider.get();
        XWiki wiki = new XWiki(xcontext.getWiki(), xcontext);
        Document configDoc = wiki.getDocumentAsAuthor(NEXTCLOUD_CONFIG_REFERENCE);
        ObjectMapper objectMapper = new ObjectMapper();
        for (Object obj : configDoc.getObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj == null) {
                continue;
            }

            Map<String, String> codes = getCodeFromObj(obj);
            if (codes.containsKey(code)
                && redirectUri.equals((String) obj.getValue(PROP_REDIRECT_URI))
            ) {
                String user = codes.get(code);
                String clientId = (String) obj.getValue(PROP_CLIENT_ID);
                codes.remove(code);
                obj.set(PROP_CODES, objectMapper.writeValueAsString(codes));
                configDoc.saveAsAuthor("Removed a code");
                return Arrays.asList(clientId, user);
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
        if (clientId == null || redirectUri == null) {
            return false;
        }

        XWikiContext xcontext = xcontextProvider.get();
        XWiki wiki = new XWiki(xcontext.getWiki(), xcontext);
        Document configDoc = wiki.getDocumentAsAuthor​(NEXTCLOUD_CONFIG_REFERENCE);
        for (Object obj : configDoc.getObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj != null
                && clientId.equals((String) obj.getValue(PROP_CLIENT_ID))
                && redirectUri.equals((String) obj.getValue(PROP_REDIRECT_URI))
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return a new grant code for a Nextcloud instance
     * @param clientId the client ID of the Nextcloud instance
     * @param redirectUri the redirectUri of the Nextcloud instance
     * @throws XWikiException when it fails to get/set information from the wiki
     * @throws JsonProcessingException when it fails handle the JSON object where the codes are stored
     */
    public String generateGrantCode(String clientId, String redirectUri)
        throws XWikiException, JsonProcessingException
    {
        if (clientId == null || redirectUri == null) {
            return "";
        }

        XWikiContext xcontext = xcontextProvider.get();
        XWiki wiki = new XWiki(xcontext.getWiki(), xcontext);
        Document configDoc = wiki.getDocumentAsAuthor​(NEXTCLOUD_CONFIG_REFERENCE);
        for (Object obj : configDoc.getObjects(NEXTCLOUD_INSTANCE_CLASS)) {
            if (obj != null
                && clientId.equals((String) obj.getValue(PROP_CLIENT_ID))
                && redirectUri.equals((String) obj.getValue(PROP_REDIRECT_URI))
            ) {
                byte[] n = new byte[32];
                new SecureRandom().nextBytes(n);
                Map<String, String> codes = getCodeFromObj(obj);
                String code = Base64URL.encode(n).toString();
                codes.put(code, xcontext.getUserReference().toString());
                obj.set(PROP_CODES, new ObjectMapper().writeValueAsString(codes));
                configDoc.saveAsAuthor("Added code for instance " + redirectUri);
                return code;
            }
        }
        return "";
    }
}
