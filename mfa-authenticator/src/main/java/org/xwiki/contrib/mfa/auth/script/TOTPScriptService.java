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
package org.xwiki.contrib.mfa.auth.script;

import java.net.URI;
import java.net.URISyntaxException;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.mfa.auth.internal.totp.TOTPManager;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.XWikiException;

/**
 * @version $Id$
 */
@Component
@Named(TOTPScriptService.ROLEHINT)
@Singleton
public class TOTPScriptService implements ScriptService
{
    /**
     * The role hint of this component.
     */
    public static final String ROLEHINT = MFAScriptService.ROLEHINT + '.' + "totp";

    @Inject
    private TOTPManager manager;

    @Inject
    private ContextualAuthorizationManager authorization;

    /**
     * @return a new random secret
     */
    public String createSecret()
    {
        return this.manager.createSecret();
    }

    /**
     * @return the {@link URI} representation of the secret
     * @throws URISyntaxException when failing to generate the URL
     * @throws XWikiException when failing to get the current secret
     */
    public URI getTOTPURL() throws URISyntaxException, XWikiException
    {
        return this.manager.getTOTPURL();
    }

    /**
     * @param secret the secret
     * @return the {@link URI} representation of the secret
     * @throws URISyntaxException when failing to generate the URL
     */
    public URI getTOTPURL(String secret) throws URISyntaxException
    {
        return this.manager.getTOTPURL(secret);
    }

    /**
     * @param code the code to validate
     * @return true if the passed code matches the one generated for the current user
     * @throws XWikiException when failing to get the current user secret
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public boolean validate(int code) throws XWikiException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        return this.manager.validate(code);
    }

    /**
     * @param code the code to validate
     * @param secret the secret with which to validate the secret
     * @return true if the passed code matches one generated with the passed secret
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public boolean validate(int code, String secret) throws AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        return this.manager.validate(code, secret);
    }

    /**
     * @param secret the secret to store
     * @param status the status
     * @throws XWikiException when failing to store the secret
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public void storeSecret(String secret, String status) throws XWikiException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        this.manager.storeSecret(secret, status);
    }

    /**
     * @param secret the secret to store
     * @throws XWikiException when failing to store the secret
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public void storeSecret(String secret) throws XWikiException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        this.manager.storeSecret(secret);
    }

    /**
     * @return the secret
     * @throws XWikiException when failing to access the secret
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public String getSecret() throws XWikiException, AccessDeniedException
    {
        return getSecret(false);
    }

    /**
     * @param checkStatus take into account the status to return null all the time if off
     * @return the secret
     * @throws XWikiException when failing to access the secret
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public String getSecret(boolean checkStatus) throws XWikiException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        return this.manager.getSecret(checkStatus);
    }

    /**
     * @return the status
     * @throws XWikiException when failing to access the status
     */
    public String getStatus() throws XWikiException
    {
        return this.manager.getStatus();
    }

    /**
     * @param status the status
     * @throws XWikiException
     * @throws AccessDeniedException when the current author is not allowed to use this API
     */
    public void storeStatus(String status) throws XWikiException, AccessDeniedException
    {
        this.authorization.checkAccess(Right.PROGRAM);

        this.manager.storeStatus(status);
    }
}
