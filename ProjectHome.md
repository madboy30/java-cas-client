<img src='http://java-cas-client.googlecode.com/svn/trunk/java-cas-client/cas-client/src/main/resources/Chile_flag.gif' height='20' width='35' />
# **Standalone Java Cas Client** #
that allows users to authenticate and validate RubyCas Server.

The initial version was created by Mathias Richter http://mathiasrichter.blogspot.com/2008/04/standalone-java-cas-client.html,
**Edited by Gaston Quezada**

Examples:
```
AUTENTICATE

       /**
        * 
        * login 	
        * @param user
        * @param password
        * @throws Exception
        */
	public void login(String user, String password) {
	try{
		this.cas = new CasClient("https://cas.domain.cl/");
		int value = this.cas.authenticate("http://app.domain.cl", user, password);
		
                LOG.info("HTTP status : " + value  + ", token : " + this.cas.getToken());
		if ( value == HttpURLConnection.HTTP_UNAUTHORIZED ){LOG.error("unauthenticated user");}
		if ( value == HttpURLConnection.HTTP_SEE_OTHER ){LOG.info("success, redirect to " + "http://app.domain.cl");}
	}
	catch (Exception e){e.printStackTrace();}
	}//fin-metodo
```


```
VALIDATE

       /**
        * 
        * validate 	
        * @throws Exception
        */
	public void validate() {
	try{
		this.cas = new CasClient("https://cas.domain.cl/");
		int verify = this.cas.validate("http://app.domain.cl", this.cas.getToken());
		if ( verify == HttpURLConnection.HTTP_UNAUTHORIZED ){LOG.error("Unauthenticated Token");}
		if ( verify == HttpURLConnection.HTTP_OK ){LOG.info("Success Token Validated.");}

	}
	catch (Exception e){e.printStackTrace();}
	}//fin-metodo
```

# **Dependencies** #

```
	<classpathentry kind="lib" path="/libraries/httpclient/commons-codec-1.4.jar"/>
	<classpathentry kind="lib" path="/libraries/httpclient/commons-logging-1.1.1.jar"/>
	<classpathentry kind="lib" path="/libraries/httpclient/httpclient-4.1.2.jar"/>
	<classpathentry kind="lib" path="/libraries/httpclient/httpclient-cache-4.1.2.jar"/>
	<classpathentry kind="lib" path="/libraries/httpclient/httpcore-4.1.2.jar"/>
	<classpathentry kind="lib" path="/libraries/httpclient/httpmime-4.1.2.jar"/>
```


# **Workflow** #
**AUTENTICATE (HTTP POST)**
<br>
<img src='http://java-cas-client.googlecode.com/svn/trunk/java-cas-client/cas-client/src/main/resources/Autenticate.jpg' height='500' width='500' />

<b>NOTES</b>
<br>
For http 303 status, header is:<br>
<br>
<pre>
HTTP/1.1 303 See Other]<br>
Date: Thu, 02 Aug 2012 17:22:02 GMT]<br>
Server: Apache/2.2.17 (Fedora)]<br>
X-Powered-By: Phusion Passenger (mod_rails/mod_rack) 3.0.14]<br>
X-Frame-Options: sameorigin]<br>
X-XSS-Protection: 1; mode=block]<br>
X-Runtime: 0.051790]<br>
Set-Cookie: tgt=TGC-1343928122r655869BF1F9DAA049E]<br>
Content-Length: 0]<br>
Location: http://app.domain.cl?ticket=ST-1343928122r154A8921246D3F07CF]<br>
Status: 303]<br>
Connection: close]<br>
Content-Type: text/html;charset=utf-8]<br>
</pre>

For http 422 status, header is:<br>
<pre>
HTTP/1.1 422 Unprocessable Entity]<br>
Date: Thu, 02 Aug 2012 16:54:10 GMT]<br>
Server: Apache/2.2.17 (Fedora)]<br>
X-Powered-By: Phusion Passenger (mod_rails/mod_rack) 3.0.14]<br>
X-Frame-Options: sameorigin]<br>
X-XSS-Protection: 1; mode=block]<br>
X-Runtime: 0.008354]<br>
Content-Length: 218]<br>
Status: 422]<br>
Connection: close]<br>
Content-Type: text/html;charset=utf-8]<br>
</pre>


<b>VALIDATE (HTTP GET)</b>
<br>
<img src='http://java-cas-client.googlecode.com/svn/trunk/java-cas-client/cas-client/src/main/resources/Validate.jpg' height='500' width='500' />

<b>NOTES</b>
<br>
For http 200 status, header is:<br>
<pre>
HTTP/1.1 200 OK]<br>
Date: Thu, 02 Aug 2012 16:46:46 GMT]<br>
Server: Apache/2.2.17 (Fedora)]<br>
X-Powered-By: Phusion Passenger (mod_rails/mod_rack) 3.0.14]<br>
X-Frame-Options: sameorigin]<br>
X-XSS-Protection: 1; mode=block]<br>
X-Runtime: 0.013747]<br>
Content-Length: 32]<br>
Status: 200]<br>
Connection: close]<br>
Content-Type: text/html;charset=utf-8]<br>
</pre>

For http 422 status, header is:<br>
<pre>
HTTP/1.1 422 Unprocessable Entity]<br>
Date: Thu, 02 Aug 2012 16:54:10 GMT]<br>
Server: Apache/2.2.17 (Fedora)]<br>
X-Powered-By: Phusion Passenger (mod_rails/mod_rack) 3.0.14]<br>
X-Frame-Options: sameorigin]<br>
X-XSS-Protection: 1; mode=block]<br>
X-Runtime: 0.008354]<br>
Content-Length: 218]<br>
Status: 422]<br>
Connection: close]<br>
Content-Type: text/html;charset=utf-8]<br>
</pre>