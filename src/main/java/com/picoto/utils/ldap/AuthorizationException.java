package com.picoto.utils.ldap;

public class AuthorizationException extends RuntimeException { 

    private static final long serialVersionUID = 8547745975693417047L;

    public AuthorizationException() {
        super();
    }

    public AuthorizationException(String str, Throwable t) {
        super(str, t);
    }

    public AuthorizationException(String str) {
        super(str);
    }

    public AuthorizationException(Throwable t) {
        super(t);
    }

}
