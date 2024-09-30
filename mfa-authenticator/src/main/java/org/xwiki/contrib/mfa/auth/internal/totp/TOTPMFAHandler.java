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

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.mfa.auth.MFAHandler;
import org.xwiki.model.reference.DocumentReference;

import com.xpn.xwiki.XWikiException;

/**
 * TOTP based implementation of {@link MFAHandler}.
 * 
 * @version $Id$
 */
@Component
@Singleton
public class TOTPMFAHandler implements MFAHandler
{
    @Inject
    private TOTPStore store;

    @Inject
    private Logger logger;

    @Override
    public boolean isEnabled(DocumentReference userReference)
    {
        try {
            return this.store.getSecret(userReference, true) != null;
        } catch (XWikiException e) {
            this.logger.error("Failed to get the TOTP secret for current user");

            return false;
        }
    }
}
