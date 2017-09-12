/**
 * Licensed to Apereo under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright ownership. Apereo
 * licenses this file to you under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the License at the
 * following location:
 *
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.jasig.portlet.emailpreview.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.jcr.Node;
import javax.portlet.ActionRequest;
import javax.portlet.PortletPreferences;
import javax.portlet.PortletRequest;
import org.exoplatform.services.log.Log;
import org.apache.commons.logging.LogFactory;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.services.jcr.ext.app.SessionProviderService;
import org.exoplatform.services.jcr.ext.common.SessionProvider;
import org.jasig.portlet.emailpreview.MailStoreConfiguration;
import org.jasig.portlet.emailpreview.dao.IEmailAccountService;
import org.jasig.portlet.emailpreview.dao.MailPreferences;
import org.jasig.portlet.emailpreview.security.IStringEncryptionService;
import org.jasig.portlet.emailpreview.service.auth.IAuthenticationService;
import org.jasig.portlet.emailpreview.service.auth.IAuthenticationServiceRegistry;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.springframework.beans.factory.annotation.Autowired;
import javax.jcr.Session;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.jcr.PropertyIterator;
import javax.jcr.Property;
import javax.jcr.RepositoryException;
import org.exoplatform.forum.common.jcr.PropertyReader;
import org.exoplatform.commons.api.settings.SettingService;
import org.exoplatform.services.jcr.RepositoryService;
import org.exoplatform.services.jcr.ext.hierarchy.NodeHierarchyCreator;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.container.ExoContainerContext;

/**
 * @author Jen Bourey, jbourey@unicon.net
 * @author Drew Wills, drew@unicon.net
 */
public class SimpleServiceBroker implements IServiceBroker {

	private final String USER_SETTINGS_NODETYPE = "portlet:emailUserSettings";
	private final String PORTLET_NODETYPE_PREFIX = "portlet:";
	private final String EMAIL_NODE_HOME = "EmailPreviewPortlet";
	private final String USER_SETTINGS_PREFIX = "email-settings-";

	private IAuthenticationServiceRegistry authServiceRegistry;
	private IStringEncryptionService stringEncryptionService;
	private Map<String, IEmailAccountService> services;
	private Set<String> protocols;
	private final Log log = ExoLogger.getLogger(this.getClass());

	// Add items to this list if they are enumerated specifically in the code
	// for getConfiguration and saveConfiguration
	protected static final List<String> RESERVED_PROPERTIES = Arrays.asList(MailPreferences.HOST.getKey(),
			MailPreferences.PORT.getKey(), MailPreferences.INBOX_NAME.getKey(), MailPreferences.PROTOCOL.getKey(),
			MailPreferences.TIMEOUT.getKey(), MailPreferences.CONNECTION_TIMEOUT.getKey(),
			MailPreferences.LINK_SERVICE_KEY.getKey(), MailPreferences.AUTHENTICATION_SERVICE_KEY.getKey(),
			MailPreferences.ALLOWABLE_AUTHENTICATION_SERVICE_KEYS.getKey(), MailPreferences.USERNAME_SUFFIX.getKey(),
			MailPreferences.ALLOW_RENDERING_EMAIL_CONTENT.getKey(), MailPreferences.EWS_USE_MAIL_ATTRIBUTE.getKey(),
			MailPreferences.EXCHANGE_AUTODISCOVER.getKey(), MailPreferences.MARK_MESSAGES_AS_READ.getKey(),
			MailPreferences.DISPLAY_MAIL_ATTRIBUTE.getKey());

	public MailStoreConfiguration getConfiguration(PortletRequest request) {
		try {
			PortletPreferences prefs = request.getPreferences();
			MailStoreConfiguration config = new MailStoreConfiguration();
			Node emailUserSettingsNode = getUserSettingsNode();

			PropertyReader reader = new PropertyReader(emailUserSettingsNode);

			// Preferences specifically handled here must be added to the
			// RESERVED_PROPERTIES list. Items might
			// be listed here to set specific default values, if the values are
			// not Strings, or you just want to
			// explicitely enumerate it for easier source tracking.
			config.setHost(reader.string(PORTLET_NODETYPE_PREFIX + MailPreferences.HOST.getKey(), null));
			config.setInboxFolderName(
					reader.string(PORTLET_NODETYPE_PREFIX + MailPreferences.INBOX_NAME.getKey(), "inbox"));
			config.setProtocol(
					reader.string(PORTLET_NODETYPE_PREFIX + MailPreferences.PROTOCOL.getKey(), IServiceBroker.IMAPS));
			config.setLinkServiceKey(prefs.getValue(MailPreferences.LINK_SERVICE_KEY.getKey(), "default"));
			config.setAuthenticationServiceKey(
					prefs.getValue(MailPreferences.AUTHENTICATION_SERVICE_KEY.getKey(), null));
			String[] authServiceKeys = prefs.getValues(MailPreferences.ALLOWABLE_AUTHENTICATION_SERVICE_KEYS.getKey(),
					new String[0]);
			config.setAllowableAuthenticationServiceKeys(Arrays.asList(authServiceKeys));
			config.setUsernameSuffix(prefs.getValue(MailPreferences.USERNAME_SUFFIX.getKey(), null));
			config.setMarkMessagesAsRead(Boolean.valueOf(
					reader.string(PORTLET_NODETYPE_PREFIX + MailPreferences.MARK_MESSAGES_AS_READ.getKey(), "true")));

			config.setAllowRenderingEmailContent(
					Boolean.valueOf(prefs.getValue(MailPreferences.ALLOW_RENDERING_EMAIL_CONTENT.getKey(), "true")));

			config.setExchangeAutodiscover(
					Boolean.valueOf(prefs.getValue(MailPreferences.EXCHANGE_AUTODISCOVER.getKey(), "false")));
			config.setEwsUseMailAttribute(
					Boolean.valueOf(prefs.getValue(MailPreferences.EWS_USE_MAIL_ATTRIBUTE.getKey(), "false")));
			config.setDisplayMailAttribute(
					Boolean.valueOf(prefs.getValue(MailPreferences.DISPLAY_MAIL_ATTRIBUTE.getKey(), "false")));

			// set the port number
			try {
				int port = Integer
						.parseInt(reader.string(PORTLET_NODETYPE_PREFIX + MailPreferences.PORT.getKey(), "-1"));
				config.setPort(port);
			} catch (NumberFormatException e) {
				throw new RuntimeException(e);
			}

			// set the connection timeout
			try {
				int connectionTimeout = Integer
						.parseInt(prefs.getValue(MailPreferences.CONNECTION_TIMEOUT.getKey(), "25000"));
				config.setConnectionTimeout(connectionTimeout);
			} catch (NumberFormatException e) {
				throw new RuntimeException(e);
			}

			// set the timeout
			try {
				int timeout = Integer.parseInt(prefs.getValue(MailPreferences.TIMEOUT.getKey(), "25000"));
				config.setTimeout(timeout);
			} catch (NumberFormatException e) {
				throw new RuntimeException(e);
			}

			/*
			 * Iterate through the preferences map, adding all preferences not
			 * handled above to either the java mail properties map or the
			 * arbitrary properties map as appropriate.
			 *
			 * This code assumes that all java mail properties begin with
			 * "mail." and does now allow administrators to define arbitrary
			 * properties beginning with that string.
			 */
			Map<String, ConfigurationParameter> allParams = Collections.emptyMap(); // default
			String authKey = config.getAuthenticationServiceKey();
			IAuthenticationService authServ = authKey != null ? authServiceRegistry.getAuthenticationService(authKey)
					: null; // need Elvis operator ?:
			if (authServ != null) {
				allParams = authServ.getConfigurationParametersMap();
			}

			PropertyIterator propertiesIt = emailUserSettingsNode.getProperties(PORTLET_NODETYPE_PREFIX + "*");
			while (propertiesIt.hasNext()) {
				Property prop = (Property) propertiesIt.next();
				String key = prop.getName().replaceFirst(PORTLET_NODETYPE_PREFIX, "");
				if (!RESERVED_PROPERTIES.contains(key) && !prop.getString().isEmpty()) {
					String value = prop.getString();

					// AuthN properties may require encryption
					ConfigurationParameter param = allParams.get(key);
					if (param != null && param.isEncryptionRequired()) {
						if (stringEncryptionService == null) {
							final String msg = "The following setting requires "
									+ "encryption but the 'stringEncryptionService' " + "bean is not configured:  "
									+ key;
							throw new IllegalStateException(msg);
						}
						try {
							value = stringEncryptionService.decrypt(value);
						} catch (EncryptionOperationNotPossibleException eonpe) {
							log.warn("Failed to decrypt a configuration " + "parameter -- did the encrytion password "
									+ "change?  (it shouldn't)", eonpe);
							// provide a dummy value for safety (a blank value
							// would make the portlet seem unconfigured)
							value = "xxx";
						}

						config.getAdditionalProperties().put(key, value);
					}
				}
			}
			
			Map<String, String[]> preferenceMap = prefs.getMap();
			for (Map.Entry<String, String[]> entry : preferenceMap.entrySet()) {
				String key = entry.getKey();
				if (!RESERVED_PROPERTIES.contains(key) && entry.getValue().length > 0) {
					String value = entry.getValue()[0];
					if (key.startsWith("mail.")) {
						config.getJavaMailProperties().put(key, value);
					}
				}
			}
			return config;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void saveConfiguration(ActionRequest request, MailStoreConfiguration config) {
		try {
			PortletPreferences prefs = request.getPreferences();
			Node emailUserSettingNode = getUserSettingsNode();
			// Start with a clean EmailPreviewPortlet
			Set<String> prefNames = new HashSet<String>(prefs.getMap().keySet());
			for (String name : prefNames) {
				if (!prefs.isReadOnly(name)) {
					prefs.reset(name);
				}
			}

			// Reserved Properties
			if (!prefs.isReadOnly(MailPreferences.HOST.getKey())) {
				emailUserSettingNode.setProperty(PORTLET_NODETYPE_PREFIX + MailPreferences.HOST.getKey(),
						config.getHost());
			}
			if (!prefs.isReadOnly(MailPreferences.PROTOCOL.getKey())) {
				emailUserSettingNode.setProperty(PORTLET_NODETYPE_PREFIX + MailPreferences.PROTOCOL.getKey(),
						config.getProtocol());
			}
			if (!prefs.isReadOnly(MailPreferences.INBOX_NAME.getKey())) {
				emailUserSettingNode.setProperty(PORTLET_NODETYPE_PREFIX + MailPreferences.INBOX_NAME.getKey(),
						config.getInboxFolderName());
			}
			if (!prefs.isReadOnly(MailPreferences.PORT.getKey())) {
				emailUserSettingNode.setProperty(PORTLET_NODETYPE_PREFIX + MailPreferences.PORT.getKey(),
						String.valueOf(config.getPort()));
			}
			if (!prefs.isReadOnly(MailPreferences.CONNECTION_TIMEOUT.getKey())) {
				prefs.setValue(MailPreferences.CONNECTION_TIMEOUT.getKey(),
						String.valueOf(config.getConnectionTimeout()));
			}
			if (!prefs.isReadOnly(MailPreferences.TIMEOUT.getKey())) {
				prefs.setValue(MailPreferences.TIMEOUT.getKey(), String.valueOf(config.getTimeout()));
			}
			if (!prefs.isReadOnly(MailPreferences.LINK_SERVICE_KEY.getKey())) {
				prefs.setValue(MailPreferences.LINK_SERVICE_KEY.getKey(), String.valueOf(config.getLinkServiceKey()));
			}
			if (!prefs.isReadOnly(MailPreferences.AUTHENTICATION_SERVICE_KEY.getKey())) {
				prefs.setValue(MailPreferences.AUTHENTICATION_SERVICE_KEY.getKey(),
						config.getAuthenticationServiceKey());
			}
			if (!prefs.isReadOnly(MailPreferences.MARK_MESSAGES_AS_READ.getKey())) {
				emailUserSettingNode.setProperty(
						PORTLET_NODETYPE_PREFIX + MailPreferences.MARK_MESSAGES_AS_READ.getKey(),
						String.valueOf(config.getMarkMessagesAsRead()));
			}
			if (!prefs.isReadOnly(MailPreferences.ALLOWABLE_AUTHENTICATION_SERVICE_KEYS.getKey())) {
				prefs.setValues(MailPreferences.ALLOWABLE_AUTHENTICATION_SERVICE_KEYS.getKey(),
						config.getAllowableAuthenticationServiceKeys().toArray(new String[0]));
			}
			if (!prefs.isReadOnly(MailPreferences.USERNAME_SUFFIX.getKey())) {
				prefs.setValue(MailPreferences.USERNAME_SUFFIX.getKey(), config.getUsernameSuffix());
			}

			if (!prefs.isReadOnly(MailPreferences.ALLOW_RENDERING_EMAIL_CONTENT.getKey())) {
				prefs.setValue(MailPreferences.ALLOW_RENDERING_EMAIL_CONTENT.getKey(),
						String.valueOf(config.getAllowRenderingEmailContent()));
			}
			if (!prefs.isReadOnly(MailPreferences.EXCHANGE_AUTODISCOVER.getKey())) {
				prefs.setValue(MailPreferences.EXCHANGE_AUTODISCOVER.getKey(),
						String.valueOf(config.isExchangeAutodiscover()));
			}
			if (!prefs.isReadOnly(MailPreferences.EWS_USE_MAIL_ATTRIBUTE.getKey())) {
				prefs.setValue(MailPreferences.EWS_USE_MAIL_ATTRIBUTE.getKey(),
						String.valueOf(config.isEwsUseMailAttribute()));
			}
			if (!prefs.isReadOnly(MailPreferences.DISPLAY_MAIL_ATTRIBUTE.getKey())) {
				prefs.setValue(MailPreferences.DISPLAY_MAIL_ATTRIBUTE.getKey(),
						String.valueOf(config.isDisplayMailAttribute()));
			}

			// JavaMail properties
			for (Map.Entry<String, String> entry : config.getJavaMailProperties().entrySet()) {
				if (!prefs.isReadOnly(entry.getKey())) {
					prefs.setValue(entry.getKey(), entry.getValue());
				}
			}

			// Additional properties (authN, etc.)
			Map<String, ConfigurationParameter> allParams = Collections.emptyMap(); // default
			String authKey = config.getAuthenticationServiceKey();
			IAuthenticationService authServ = authKey != null ? authServiceRegistry.getAuthenticationService(authKey)
					: null; // need Elvis operator ?:
			if (authServ != null) {
				allParams = authServ.getConfigurationParametersMap();
			}
			for (Map.Entry<String, String> entry : config.getAdditionalProperties().entrySet()) {
				if (!prefs.isReadOnly(entry.getKey()) && (entry.getKey().equals(MailPreferences.PASSWORD.getKey())
						|| entry.getKey().equals(MailPreferences.MAIL_ACCOUNT.getKey()))) {
					String key = entry.getKey();
					String value = entry.getValue();
					ConfigurationParameter param = allParams.get(entry.getKey());
					if (param != null && param.isEncryptionRequired()) {
						if (stringEncryptionService == null) {
							final String msg = "The following setting requires "
									+ "encryption but the 'stringEncryptionService' " + "bean is not configured:  "
									+ entry.getKey();
							throw new IllegalStateException(msg);
						}
						value = stringEncryptionService.encrypt(value);
					}
					emailUserSettingNode.setProperty(PORTLET_NODETYPE_PREFIX + key, value);
				}
			}
			emailUserSettingNode.getSession().save();
			prefs.store();
		} catch (Exception e) {
			log.error(e);
		}
	}

	@Override
	public IEmailAccountService getEmailAccountService(PortletRequest request) {
		Node emailUserSettingsNode = null;
		try {
			emailUserSettingsNode = getUserSettingsNode();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		PropertyReader reader = new PropertyReader(emailUserSettingsNode);
		String protocol = reader.string("portlet" + MailPreferences.PROTOCOL.getKey(), IServiceBroker.IMAPS);
		return services.get(protocol);
	}

	@Autowired
	public void setAuthenticationServiceRegistry(IAuthenticationServiceRegistry authServiceRegistry) {
		this.authServiceRegistry = authServiceRegistry;
	}

	@Autowired(required = false)
	public void setStringEncryptionService(IStringEncryptionService stringEncryptionService) {
		this.stringEncryptionService = stringEncryptionService;
	}

	public Map<String, IEmailAccountService> getServices() {
		return services;
	}

	public void setServices(Map<String, IEmailAccountService> services) {
		this.services = services;
		this.protocols = Collections.unmodifiableSortedSet(new TreeSet<String>(services.keySet()));
	}

	public Set<String> getSupportedProtocols() {
		return protocols;
	}

	public static <T> T getComponent(Class<T> type) {
		return type.cast(PortalContainer.getInstance().getComponentInstanceOfType(type));
	}

	public Node getUserSettingsNode() throws Exception {
		SessionProvider sProvider = SessionProvider.createSystemProvider();
		String userId = ConversationState.getCurrent().getIdentity().getUserId();

		if (userId != null) {

			NodeHierarchyCreator nodeCreator = (NodeHierarchyCreator) ExoContainerContext.getCurrentContainer()
					.getComponentInstanceOfType(NodeHierarchyCreator.class);
			Node userPrivateNode = nodeCreator.getUserNode(sProvider, userId).getNode("ApplicationData");
			if (!userPrivateNode.hasNode(EMAIL_NODE_HOME)) {
				Node emailUserSettingHomeNode = userPrivateNode.addNode(EMAIL_NODE_HOME, "nt:unstructured");
				userPrivateNode.save();
				emailUserSettingHomeNode.save();
			}

			if (!userPrivateNode.getNode(EMAIL_NODE_HOME).hasNode(USER_SETTINGS_PREFIX + userId)) {
				Node emailUserSettingHomeNode = userPrivateNode.getNode(EMAIL_NODE_HOME);
				Node emailUserSettingNode = emailUserSettingHomeNode.addNode(USER_SETTINGS_PREFIX + userId,
						USER_SETTINGS_NODETYPE);
				userPrivateNode.save();
				emailUserSettingHomeNode.save();
				emailUserSettingNode.save();
			}

			Node emailUserSettingNode = userPrivateNode.getNode(EMAIL_NODE_HOME).getNode(USER_SETTINGS_PREFIX + userId);
			return emailUserSettingNode;
		}
		return null;
	}
}
