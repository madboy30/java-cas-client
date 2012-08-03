/**
 * 
 */
package cl.gqtech.cas.client;

import java.net.HttpURLConnection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import javax.net.ssl.*;

public class CasClient{
  
   public static Logger LOG = Logger.getLogger( CasClient.class  );

   public static final String LOGIN_URL_PART = "login";
   public static final String SERVICE_VALIDATE_URL_PART = "serviceValidate";
   public static final String TICKET_BEGIN = "ticket=";
   private static final String LT_BEGIN = "name=\"lt\" value=\"";
   public static final String CAS_USER_BEGIN = "<cas:user>";
   public static final String CAS_USER_END = "</cas:user>";
   
   private HttpClient fClient = new DefaultHttpClient();
   private String fCasUrl;
   private String token = null;
   
   
  /**
   * Construct a new CasClient.
   *
   * @param casUrl The base URL of the CAS service to be used.
   */
   public CasClient( String casBaseUrl ){this( new DefaultHttpClient(), casBaseUrl );}
  
  /**
   * Construct a new CasClient which uses the specified HttpClient
   * for its HTTP calls.
   *
   * @param client
   * @param casBaseUrl
   */
   public CasClient( HttpClient client, String casBaseUrl ){fClient = client;fCasUrl = casBaseUrl;}

  /**
   * Validate the specified service ticket against the specified service.
   * If the ticket is valid, this will yield the clear text user name
   * of the autenticated user.<br>
   * Note that each service ticket issued by CAS can be used exactly once
   * to validate.
   *
   * @param serviceUrl
   * @param serviceTicket
   *
   * @return Clear text username of the authenticated user.
   */
   public int validate( String serviceUrl, String serviceTicket ){
   try{
	   
       HttpGet method = new HttpGet( fCasUrl + "serviceValidate?service="+ serviceUrl + "&ticket="+ serviceTicket);
       SSLContext ctx = SSLContext.getInstance("TLS");
       X509TrustManager tm = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {return null;}
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
			public void checkServerTrusted(X509Certificate[] arg0, String arg1)throws CertificateException {}
       };
	   
       ctx.init(null, new TrustManager[]{tm}, null);
       SSLSocketFactory ssf = new SSLSocketFactory(ctx);
       ssf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
       ClientConnectionManager ccm = fClient.getConnectionManager();
       SchemeRegistry sr = ccm.getSchemeRegistry();
       sr.register(new Scheme("https", ssf, 443));
       fClient = new DefaultHttpClient(ccm, fClient.getParams());

	   HttpResponse response = fClient.execute(method);
	   HttpEntity entity = response.getEntity();
       int statusCode = response.getStatusLine().getStatusCode();
       if (statusCode != HttpURLConnection.HTTP_OK){ LOG.error( "Could not validate: " + response.getStatusLine()); return  HttpURLConnection.HTTP_UNAUTHORIZED;} 
       else{LOG.info(extractUser( new String( EntityUtils.toString(entity)))); return  HttpURLConnection.HTTP_OK;}
   }
   catch ( Exception x ){LOG.error( "Could not validate: " + x.toString () );x.printStackTrace();}
   return HttpURLConnection.HTTP_INTERNAL_ERROR;
   }
  
   /**
    * Authenticate the specified user with the specified password against the
    * specified service.
    *
    * @param serviceUrl May be null. If a url is specified, the authentication will happen against this service, yielding a service ticket which can be validated.
    * @param username
    * @param password
    * @return A valid service ticket, if and only if the specified service URL is not null.
    */
   public int authenticate( String serviceUrl, String username, String password ){
   try{	   
	        String lt = getLt( serviceUrl );
	        if ( lt == null ){
	             LOG.error( "Cannot retrieve LT from CAS. Aborting authentication for '" + username + "'" );
	             return HttpURLConnection.HTTP_INTERNAL_ERROR;
	        }
       
            HttpPost method = new HttpPost( fCasUrl + LOGIN_URL_PART );
	        HttpParams params = new BasicHttpParams();
	        params.setParameter("http.protocol.handle-redirects",false);
            method.setParams(params);
	        
            List <NameValuePair> nvps = new ArrayList <NameValuePair>(); 
            nvps.add(new BasicNameValuePair("username", username)); 
            nvps.add(new BasicNameValuePair("lt", lt)); 
            nvps.add(new BasicNameValuePair("service", serviceUrl));
            nvps.add(new BasicNameValuePair("password", password));
            method.setEntity((HttpEntity) new UrlEncodedFormEntity(nvps, HTTP.UTF_8));
//          method.getParams().setParameter( "_eventId", "submit" );
//          method.getParams().setParameter( "gateway", "true" );
    	    
            SSLContext ctx = SSLContext.getInstance("TLS");
	        X509TrustManager tm = new X509TrustManager() {
	            public X509Certificate[] getAcceptedIssuers() {return null;}
				public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
				public void checkServerTrusted(X509Certificate[] arg0, String arg1)throws CertificateException {}
	        };

            ctx.init(null, new TrustManager[]{tm}, null);
	        SSLSocketFactory ssf = new SSLSocketFactory(ctx);
	        ssf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
	        ClientConnectionManager ccm = fClient.getConnectionManager();
	        SchemeRegistry sr = ccm.getSchemeRegistry();
	        sr.register(new Scheme("https", ssf, 443));
	        fClient = new DefaultHttpClient(ccm, fClient.getParams());
	        

	        
	        
	        HttpResponse response = fClient.execute(method);
	        Header[] head = response.getAllHeaders();
	        for ( int i = 0; i < head.length; i++ ){
	        	   LOG.debug("@@@@@@@@@@@@@@" + head[i].getName() + ":" + head[i].getValue());
	        	   if ( head[i].getName().trim().equals("Location") == true ){this.setToken(this.extractServiceTicket(head[i].getValue()));}
	        }
	        
	        HttpEntity entity = response.getEntity();
	        LOG.info(EntityUtils.toString(entity));
	        
            
       	    int statusCode = Integer.parseInt(String.valueOf(response.getStatusLine().getStatusCode()));
            return statusCode;       	    
       	    
   } 
   catch ( Exception x ){LOG.error( "Could not authenticate'" + username + "':" + x.toString () );}
   return HttpURLConnection.HTTP_INTERNAL_ERROR;
   }//fin-metodo
  
  /**
   * Helper method to extract the user name from a "service validate" call to CAS.
   *
   * @param data Response data.
   * @return The clear text username, if it could be extracted, null otherwise.
   */
   protected String extractUser( String data ){
       String user = null;
       int start = data.indexOf( CAS_USER_BEGIN  );
       if ( start >= 0 ){
           start += CAS_USER_BEGIN.length();
           int end = data.indexOf( CAS_USER_END );
           if ( end > start )
               user = data.substring( start, end );
           else
               LOG.warn( "Could not extract username from CAS validation response. Raw data is: '" + data + "'" );
       }
       else{LOG.warn( "Could not extract username from CAS validation response. Raw data is: '" + data + "'" );}
       return user;
   }//fin-metodo
  
  /**
   * Helper method to extract the service ticket from a login call to CAS.
   *
   * @param data Response data.
   * @return The service ticket, if it could be extracted, null otherwise.
   */
   protected String extractServiceTicket( String data ){
       String serviceTicket = null;
       int start = data.indexOf( TICKET_BEGIN  );
       if ( start > 0 ){
           start += TICKET_BEGIN.length();
           serviceTicket = data.substring( start );
       }
       return serviceTicket;
   }//fin-metodo
  
  /**
   * Helper method to extract the LT from a login form from CAS.
   *
   * @param data Response data.
   * @return The LT, if it could be extracted, null otherwise.
   */
   protected String extractLt( String data ){
       String token = null;
       int start = data.indexOf( LT_BEGIN  );
       if ( start < 0 )
       {
           LOG.error( "Could not obtain LT token from CAS: LT Token not found in response." );
       } else
       {
           start += LT_BEGIN.length();
           int end = data.indexOf( "\"", start );
           token = data.substring( start, end );
       }       
   return data;
   }//fin-metodo
  
  /**
   * This method requests the original login form from CAS.
   * This form contains an LT, an initial token that must be
   * presented to CAS upon sending it an authentication request
   * with credentials.<br>
   * If a service URL is provided (which is optional), this method
   * will post the URL such that CAS authenticates against the
   * specified service when a subsequent authentication request is
   * sent.
   *
   * @param serviceUrl
   * @return The LT token if it could be extracted from the CAS response.
   */
   protected String getLt( String serviceUrl ){
       String lt = null;
       if ( serviceUrl == null ){}
       else{
           HttpPost method = new HttpPost( fCasUrl + LOGIN_URL_PART + "Ticket" );
           method.getParams().setParameter("service", serviceUrl);
           
           try{
               SSLContext ctx = SSLContext.getInstance("TLS");
    	       X509TrustManager tm = new X509TrustManager() {
    	            public X509Certificate[] getAcceptedIssuers() {return null;}
    				public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
    				public void checkServerTrusted(X509Certificate[] arg0, String arg1)throws CertificateException {}
    	       };
        	   
               ctx.init(null, new TrustManager[]{tm}, null);
    	       SSLSocketFactory ssf = new SSLSocketFactory(ctx);
    	       ssf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    	       ClientConnectionManager ccm = fClient.getConnectionManager();
    	       SchemeRegistry sr = ccm.getSchemeRegistry();
    	       sr.register(new Scheme("https", ssf, 443));
    	       fClient = new DefaultHttpClient(ccm, fClient.getParams());

        	   HttpResponse response = fClient.execute(method);
        	   HttpEntity entity = response.getEntity();
        	   
               int statusCode = Integer.parseInt(String.valueOf(response.getStatusLine().getStatusCode()));
               if (statusCode != HttpURLConnection.HTTP_OK){
                   LOG.error( "Could not obtain LT token from CAS: " + response.getStatusLine() );
               } 
               else{this.setToken(EntityUtils.toString(entity)); return this.getToken();}
           }
           catch ( Exception x ){x.printStackTrace(); LOG.error( "Could not obtain LT token from CAS: " + x.toString () );}
       }
       return lt;
   }//fin-metodo


  /**
   * Return token for validate user.
   * 
   * @return the token
   */
   public String getToken() {return token;}
   	

  /**
   * @param token the token to set
   */
   protected void setToken(String token) {this.token = token;}
   
}//fin-clase