package com.picoto.utils.ldap;


public interface AuthorizationService {

    public boolean authenticate(String user, String passwd);

    public String getAttribute(final String user, final String attribute);

    public boolean isUserInRole(String user, String group);

}
