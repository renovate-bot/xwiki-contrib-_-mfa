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
package org.xwiki.contrib.mfa.auth.internal;

import java.net.URL;
import java.security.Principal;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.container.servlet.HttpServletUtils;
import org.xwiki.contrib.mfa.auth.MFAHandler;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * Expose the MFA bridge authenticator as component.
 * 
 * @version $Id$
 */
@Component
@Singleton
@Named(MFABridgeAuthService.ID)
public class MFABridgeAuthService implements XWikiAuthServiceComponent
{
    /**
     * The identifier of the authenticator.
     */
    public static final String ID = "mfa-bridge";

    @Inject
    private MFABridgeConfiguration configuration;

    @Inject
    private MFAManager manager;

    @Inject
    @Named("context")
    private ComponentManager componentManager;

    @Inject
    private Logger logger;

    @Override
    public String getId()
    {
        return ID;
    }

    private boolean isEnabled(DocumentReference userReference)
    {
        try {
            for (MFAHandler handler : this.componentManager.<MFAHandler>getInstanceList(MFAHandler.class)) {
                if (handler.isEnabled(userReference)) {
                    return true;
                }
            }
        } catch (ComponentLookupException e) {
            this.logger.error("Failed to check the status");
        }

        return false;
    }

    private void redirect(XWikiContext context)
    {
        try {
            // Remember the current URL
            URL souceURL = HttpServletUtils.getSourceURL(context.getRequest());

            // Redirect to the MFA handler
            context.getResponse().sendRedirect(this.manager.createBaseEndPointURI(souceURL.toString()));
        } catch (Exception e) {
            logger.error("Failed to check MFA", e);
        }
    }

    private XWikiUser checkXWikiUser(XWikiUser user, XWikiContext context)
    {
        // If the user is authenticated, make sure the configured 2FA was validated
        if (user != null && !this.configuration.isValid() && isEnabled(user.getUserReference())) {
            // Remember the user
            this.configuration.setUserReference(user.getUserReference());

            // Redirect to the MFA handler
            redirect(context);

            return null;
        }

        return user;
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        // Check if the MFA process started
        DocumentReference sessionUser = this.configuration.getUserReference();
        if (sessionUser != null) {
            // Check if the user MFA was validated
            if (this.configuration.isValid()) {
                // Since it's valid we stop the process
                this.configuration.removeUserReference();

                return new XWikiUser(sessionUser);
            }

            // Redirect to the MFA handler if still invalid
            redirect(context);
        }

        // Start regular authentication
        return checkXWikiUser(this.configuration.getAuthenticator().checkAuth(context), context);
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        return checkXWikiUser(this.configuration.getAuthenticator().checkAuth(username, password, rememberme, context),
            context);
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        this.configuration.getAuthenticator().showLogin(context);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        Principal principal = this.configuration.getAuthenticator().authenticate(username, password, context);

        if (principal == null) {
            return null;
        }

        if (checkXWikiUser(new XWikiUser(principal.getName()), context) != null) {
            return principal;
        }

        return null;
    }
}
