1.- You must include this project as a dependency in your application.
2.- You must define in the Spring context a variable of type String called: ldapURL
3.- Your ldap must allow read access to non authenticated users
4.- Configure your ldap domain using the variable: <property name="base" value="dc=xxxxx,dc=yyyyy" />