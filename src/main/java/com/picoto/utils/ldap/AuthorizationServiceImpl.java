package com.picoto.utils.ldap;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.LdapTemplate;

public class AuthorizationServiceImpl implements AuthorizationService {

    public static final String CN = "cn";

    public static final String CNEQUAL = CN + "=";

    private static final String USERS = CNEQUAL + "users";

    private static final String GROUPS = CNEQUAL + "Groups";

    private static final String UNIQUEMEMBER = "uniquemember=" + CNEQUAL;

    public static final int DEFAULT_RECURSION_LEVEL = 6;

    protected static final Logger log = LoggerFactory.getLogger(AuthorizationServiceImpl.class);

    private LdapTemplate pooledLdapTemplate;

    private List<String> revisados = new ArrayList<String>();

    private String getUserFilter(String user) {
        return "(&(" + CNEQUAL + user + ")(objectclass=person))";
    }

    @Override
    public boolean authenticate(String user, String passwd) {
        log.info("Autenticado usuario: " + user);
        return pooledLdapTemplate.authenticate(USERS, getUserFilter(user), passwd);
    }

    @SuppressWarnings("unchecked")
    @Override
    public String getAttribute(final String user, final String attribute) {
        try {
            log.info("Recuperando credencial: " + user);
            List<String> res = pooledLdapTemplate.search(USERS, getUserFilter(user),
                    new AttributesMapper() {

                        @Override
                        public Object mapFromAttributes(Attributes attrs) throws NamingException {
                            Attribute title = attrs.get(attribute);
                            if (title != null) {
                                return title.get();
                            } else {
                                return user;
                            }
                        }

                    });
            if (res.size() == 1) {
                String credencial = res.get(0);
                log.info("La credencial recuperada es: " + credencial);
                return credencial;
            } else {
                log.error("No se ha podido recuperar la credencial");
                throw new AuthorizationException("Usuario no encontrado o duplicado en LDAP: "
                        + user);
            }
        } catch (Exception e) {
            log.error("No se ha podido recuperar la credencial", e);
            throw new AuthorizationException(e);
        }
    }

    @Override
    public boolean isUserInRole(String user, String group) {
        return isUserInRole(user, group, DEFAULT_RECURSION_LEVEL);
    }

    @SuppressWarnings({"unchecked" })
    protected boolean isUserInRole(String user, String group, int maxRecursionLevel) {
        try {

            if (maxRecursionLevel <= 0) {
                log.error("Se ha alcanzado el limite de recursion sin encontrar el grupo " + group
                        + " buscado para el usuario: " + user);
                return false;
            }

            if (maxRecursionLevel == DEFAULT_RECURSION_LEVEL) {
                revisados.clear();
            }

            log.info("Buscando grupos de nivel " + maxRecursionLevel + " que contengan a : " + user);

            List<String> groups = pooledLdapTemplate.search(GROUPS, getUniqueMember(user),
                    new CustomContextMapper());
            // Miramos los grupos a los que pertenece el usuario y si alguno es
            // el buscado, entonces acabamos
            for (String currentGroup : groups) {
                if (StringUtils.equalsIgnoreCase(group, currentGroup)) {
                    log.info("El usuario se encuentra finalmente asociado al grupo: " + group);
                    return true;
                }
            }
            // En caso contrario para cada uno de los roles que tiene el
            // usuario, vemos si ese role pertence al grupo que buscamos
            for (String currentRole : groups) {
                if (!revisados.contains(currentRole)) {
                    revisados.add(currentRole);
                    log.info("Recursion : " + currentRole);
                    if (isUserInRole(currentRole, group, maxRecursionLevel - 1)) {
                        log.info("El usuario se encuentra asociado al grupo: " + group
                                + " mediante el grupo: " + currentRole);
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error recuperando roles...", e);
        }
        return false;
    }

    private String getUniqueMember(String user) {
        return "(&(" + UNIQUEMEMBER + user + ",*)(objectclass=groupOfUniqueNames))";
    }

    public LdapTemplate getPooledLdapTemplate() {
        return pooledLdapTemplate;
    }

    public void setPooledLdapTemplate(LdapTemplate pooledLdapTemplate) {
        this.pooledLdapTemplate = pooledLdapTemplate;
    }

}

class CustomContextMapper implements ContextMapper {

    @Override
    public Object mapFromContext(Object ctx) {
        DirContextAdapter context = (DirContextAdapter) ctx;
        String cn = (String) context.getObjectAttribute(AuthorizationServiceImpl.CN);
        return cn;
    }

}
