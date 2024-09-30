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

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.cryptacular.generator.TOTPGenerator;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.HttpServletUtils;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.model.reference.EntityReferenceSerializer;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * @version $Id$
 */
@Component(roles = TOTPManager.class)
@Singleton
public class TOTPManager
{
    @Inject
    private TOTPStore store;

    @Inject
    private Container container;

    @Inject
    private EntityReferenceSerializer<String> serializer;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    /**
     * @param code the code to validate
     * @return true if the passed code matches the one generated for the current user
     * @throws XWikiException when failing to get the current user secret
     */
    public boolean validate(int code) throws XWikiException
    {
        return validate(code, this.store.getSecret(true));
    }

    /**
     * @param code the code to validate
     * @param secret the secret with which to validate the secret
     * @return true if the passed code matches one generated with the passed secret
     */
    public boolean validate(int code, String secret)
    {
        TOTPGenerator generator = new org.cryptacular.generator.TOTPGenerator();

        return code == generator.generate(new org.apache.commons.codec.binary.Base32().decode(secret));
    }

    /**
     * @return a new random secret
     */
    public String createSecret()
    {
        SecureRandom random = new SecureRandom();
        byte[] secretBytes = new byte[64];
        random.nextBytes(secretBytes);

        return new org.apache.commons.codec.binary.Base32().encodeAsString(secretBytes);
    }

    /**
     * @param secret the secret to store
     * @throws XWikiException when failing to store the secret
     */
    public void storeSecret(String secret) throws XWikiException
    {
        this.store.storeSecret(secret);
    }

    /**
     * @param secret the secret to store
     * @param status the status
     * @throws XWikiException when failing to store the secret
     */
    public void storeSecret(String secret, String status) throws XWikiException
    {
        this.store.storeSecret(secret, status);
    }

    /**
     * @return the {@link URI} representation of the secret
     * @throws URISyntaxException when failing to generate the URL
     * @throws XWikiException when failing to get the secret
     */
    public URI getTOTPURL() throws URISyntaxException, XWikiException
    {
        String secret = this.store.getSecret(false);

        return secret != null ? getTOTPURL(secret) : null;
    }

    /**
     * @param secret the secret
     * @return the {@link URI} representation of the secret
     * @throws URISyntaxException when failing to generate the URL
     */
    public URI getTOTPURL(String secret) throws URISyntaxException
    {
        ServletRequest request = (ServletRequest) this.container.getRequest();

        URL sourceURL = HttpServletUtils.getSourceBaseURL(request.getHttpServletRequest());

        return new URI("otpauth://totp/" + sourceURL.getHost() + "@"
            + URLEncoder.encode(this.serializer.serialize(this.xcontextProvider.get().getUserReference()),
                StandardCharsets.UTF_8)
            + "?issuer=" + URLEncoder.encode(sourceURL.getHost(), StandardCharsets.UTF_8) + "&secret="
            + URLEncoder.encode(secret, StandardCharsets.UTF_8));
    }

    /**
     * @return the status
     * @throws XWikiException when failing to access the status
     */
    public String getStatus() throws XWikiException
    {
        return this.store.getStatus();
    }

    /**
     * @param status the status
     * @throws XWikiException
     */
    public void storeStatus(String status) throws XWikiException
    {
        this.store.storeStatus(status);
    }

    /**
     * @param checkStatus take into account the status to return null all the time if off
     * @return the secret
     * @throws XWikiException when failing to access the secret
     */
    public String getSecret(boolean checkStatus) throws XWikiException
    {
        return this.store.getSecret(checkStatus);
    }
}
