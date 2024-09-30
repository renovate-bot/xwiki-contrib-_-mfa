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
package org.xwiki.contrib.mfa.auth.internal.totp;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * @version $Id$
 */
@Component(roles = TOTPStore.class)
@Singleton
public class TOTPStore
{
    private static final LocalDocumentReference TOTP_CLASS_REFERRENCE =
        new LocalDocumentReference(List.of("XWiki", "MFA", "TOTP"), "TOTPClass");

    private static final String PROP_SECRET = "secret";

    private static final String PROP_STATUS = "status";

    private static final String STATUS_ON = "on";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    /**
     * @param create true if the object should be created if it does not exist
     * @param xcontext the XWiki Context
     * @return the object containing the TOTP configuration for the current user
     * @throws XWikiException when failing to access the object
     */
    public BaseObject getXObject(boolean create, XWikiContext xcontext) throws XWikiException
    {
        return getXObject(xcontext.getUserReference(), create, xcontext);
    }

    /**
     * @param userReference the reference of the user
     * @param create true if the object should be created if it does not exist
     * @param xcontext the XWiki Context
     * @return the object containing the TOTP configuration for the current user
     * @throws XWikiException when failing to access the object
     */
    public BaseObject getXObject(DocumentReference userReference, boolean create, XWikiContext xcontext)
        throws XWikiException
    {
        BaseObject totpObject = null;

        if (userReference != null) {
            XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);

            // Check if the user exist
            if (!userDocument.isNew()) {
                // Clone the document to be safe
                userDocument = userDocument.clone();

                // Get the object (create it if needed)
                totpObject = userDocument.getXObject(TOTP_CLASS_REFERRENCE, true, xcontext);

                return totpObject;
            }
        }

        if (create) {
            throw new XWikiException(XWikiException.ERROR_XWIKI_UNKNOWN, XWikiException.ERROR_XWIKI_UNKNOWN,
                "The user does not exist");
        }

        return null;
    }

    /**
     * @param checkStatus take into account the status to return null all the time if off
     * @return the stored secret
     * @throws XWikiException when failing to access the stored secret
     */
    public String getSecret(boolean checkStatus) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject totpObject = getXObject(false, xcontext);

        return getSecret(totpObject, checkStatus);
    }

    /**
     * @param userReference the reference of the user
     * @param checkStatus take into account the status to return null all the time if off
     * @return the stored secret
     * @throws XWikiException when failing to access the stored secret
     */
    public String getSecret(DocumentReference userReference, boolean checkStatus) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject totpObject = getXObject(userReference, false, xcontext);

        return getSecret(totpObject, checkStatus);
    }

    private String getSecret(BaseObject totpObject, boolean checkStatus)
    {
        if (totpObject != null) {
            if (!checkStatus || STATUS_ON.equals(totpObject.getStringValue(PROP_STATUS))) {
                return StringUtils.defaultIfBlank(totpObject.getStringValue(PROP_SECRET), null);
            }
        }

        return null;
    }

    /**
     * @param secret the secret to store
     * @throws XWikiException when failing to store the secret
     */
    public void storeSecret(String secret) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject totpObject = getXObject(true, xcontext);

        totpObject.setStringValue(PROP_SECRET, secret);

        xcontext.getWiki().saveDocument(totpObject.getOwnerDocument(), xcontext);
    }

    /**
     * @param secret the secret to store
     * @param status the status
     * @throws XWikiException when failing to store the secret
     */
    public void storeSecret(String secret, String status) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject totpObject = getXObject(true, xcontext);

        totpObject.setStringValue(PROP_SECRET, secret);
        totpObject.setStringValue(PROP_STATUS, status);

        xcontext.getWiki().saveDocument(totpObject.getOwnerDocument(), xcontext);
    }

    /**
     * @return the status
     * @throws XWikiException when failing to access the status
     */
    public String getStatus() throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject totpObject = getXObject(false, xcontext);

        if (totpObject != null) {
            if (STATUS_ON.equals(totpObject.getStringValue(PROP_STATUS))) {
                return totpObject.getStringValue(PROP_STATUS);
            }
        }

        return null;
    }

    /**
     * @param status the status
     * @throws XWikiException when failing to store the status
     */
    public void storeStatus(String status) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject totpObject = getXObject(true, xcontext);

        totpObject.setStringValue(PROP_STATUS, status);

        xcontext.getWiki().saveDocument(totpObject.getOwnerDocument(), xcontext);
    }
}
