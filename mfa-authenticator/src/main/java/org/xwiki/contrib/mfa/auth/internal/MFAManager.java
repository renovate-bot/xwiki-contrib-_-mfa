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

import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.template.TemplateManager;

import com.xpn.xwiki.XWikiContext;

/**
 * Main utility for OIDC provider.
 * 
 * @version $Id$
 */
@Component(roles = MFAManager.class)
@Singleton
public class MFAManager
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("compact")
    private EntityReferenceSerializer<String> compactReferenceSerializer;

    @Inject
    private TemplateManager templates;

    /**
     * @param redirect the URL to redirect to after the validation
     * @return the base URL
     * @throws MalformedURLException when failing to get server URL
     */
    public String createBaseEndPointURI(String redirect) throws MalformedURLException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        StringBuilder base = new StringBuilder();

        base.append(xcontext.getURLFactory().getServerURL(xcontext));

        if (base.charAt(base.length() - 1) != '/') {
            base.append('/');
        }

        String webAppPath = xcontext.getWiki().getWebAppPath(xcontext);
        if (!webAppPath.equals("/")) {
            base.append(webAppPath);
        }

        base.append("mfa");

        if (redirect != null) {
            base.append("?xredirect=");
            base.append(URLEncoder.encode(redirect, StandardCharsets.UTF_8));
        }

        return base.toString();
    }

    /**
     * Run a template and generate a HTML content response.
     * 
     * @param templateName the name of the template
     * @param response the response to fill
     * @throws Exception when failing to execute the template
     */
    public void executeTemplate(String templateName, HttpServletResponse response) throws Exception
    {
        String html = this.templates.render(templateName);

        try (Writer writer = response.getWriter()) {
            writer.write(html);
        }
    }
}
