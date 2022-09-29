/* pam_deviceauthgrant */

/* A minimal C implementation of a PAM module performing */
/* RFC 8628: OAuth 2.0 Device Authorization Grant */

/* Copyright (C) 2022  ll4il <ll4il@ilorentz.org>

/* pam_deviceauthgrant is free software: you can redistribute it and/or modify */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or */
/* (at your option) any later version. */

/* This program is distributed in the hope that it will be useful, */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the */
/* GNU General Public License for more details. */

/* You should have received a copy of the GNU General Public License */
/* along with this program.  If not, see <https://www.gnu.org/licenses/>. */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <openssl/pem.h>

//minimal json parser
#include "jsmn.h"

// session business
#include <sys/types.h>
#include <pwd.h>
#include <sys/wait.h>
#define ECHO "/bin/echo"


//added as in PAM docs
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#define AGENT "pam_deviceauthgrant"
#define AGENT_CONF_FILE "/etc/deviceauthgrant.json"

#define INIT_SIZE 2

#define B64CONV_FACTOR 0.75

// device flow polling
#define TOKEN_REQUEST_TIME_STEP 5
#define TOKEN_REQUEST_TIMEOUT 20


//oauth device flow
#define KC_USERCODE_KEY "user_code"
#define KC_DEVICECODE_KEY "device_code"
#define KC_VERIFICATION_URI_KEY "verification_uri_complete"
#define KC_ERROR_KEY "error"
#define KC_IDTOKEN_KEY "id_token"
#define KC_USERNAME_KEY "preferred_username"
#define KC_AUTH_URL_PARS "client_id=%s&client_secret=%s&cacert=%s&scope=%s"
#define KC_TOKEN_URL_PARS "device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&" KC_AUTH_URL_PARS 

#define JWT_SEPARATOR "."

enum boolean {FALSE, TRUE};

//debug utility
#define D(x) do {\
    printf ("[%s:%s(%d)] ", __FILE__, __FUNCTION__, __LINE__); \
    printf x;\
    printf ("\n"); \
  } while (0)
#define DBG(x) if (cfg.debug) {D(x);}

#define DBG_WRN   DBG (("**********************************************\n"));\
  DBG(("** REMEBER to TURN OFF debug in  PRODUCTION **\n"));		\
  DBG (("**********************************************\n"));
  

//conf file structure
typedef struct {
  char *dev_auth_url;
  char *token_url;
  char *client_id;
  char *client_secret;
  char *client_scopes;
  char *ca_certs;
} AGENT_CONFIG;

//cmd line options
struct lib_cfg
{
  int debug;
  int qrcode;
  char *agentconf;
};


//curl returns
typedef struct {
  char *payload;
  size_t size;
} C_FETCH;



static void
parse_lib_cfg (int flags, int argc, const char **argv, struct lib_cfg *cfg)
{
  int i;

  cfg->debug = 0;
  cfg->qrcode = 0;
  cfg->agentconf = NULL;
  
  for (i = 0; i < argc; i++)
    {
      if (strcmp (argv[i], "debug") == 0)
	cfg->debug = TRUE;
      if (strcmp (argv[i], "qrcode") == 0)
	cfg->qrcode = TRUE;
      if (strncmp (argv[i], "agentconf=", 10) == 0)
	cfg->agentconf = (char*) argv[i] + 10;
    }


  cfg->agentconf = cfg->agentconf == NULL ? AGENT_CONF_FILE : cfg->agentconf;
  
  if (cfg->debug)
    {
      D (("Passing the following arguments\n"));
      D (("debug=%d", cfg->debug));
      D (("qrcode=%d", cfg->qrcode));
      D (("agentconf=%s", cfg->agentconf));
    }
}



static char*
make_auth_request_body(const AGENT_CONFIG ag_conf){

  char* post_data=NULL;
  size_t post_data_needed_size = snprintf(NULL,0,KC_AUTH_URL_PARS,
					  ag_conf.client_id, ag_conf.client_secret, ag_conf.ca_certs,ag_conf.client_scopes);

  post_data = malloc(post_data_needed_size+1);
  sprintf(post_data,KC_AUTH_URL_PARS,
	  ag_conf.client_id, ag_conf.client_secret, ag_conf.ca_certs,ag_conf.client_scopes);

  return post_data;
}

static char*
make_token_request_body(const AGENT_CONFIG ag_conf,const char* devicecode){

  char* post_data=NULL;
  size_t post_data_needed_size = snprintf(NULL,0,KC_TOKEN_URL_PARS,
					  devicecode, ag_conf.client_id,ag_conf.client_secret, ag_conf.ca_certs, ag_conf.client_scopes);

  post_data = malloc(post_data_needed_size+1);
  sprintf(post_data,KC_TOKEN_URL_PARS,
	  devicecode, ag_conf.client_id,ag_conf.client_secret, ag_conf.ca_certs, ag_conf.client_scopes);

  return post_data;

}


static int
jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}



static int
read_json_response_dynamic(const C_FETCH response,const char* key, char** value){
  int r,i;
  jsmn_parser p;

  jsmntok_t *t; // unknown num tokens
  size_t tokcount = INIT_SIZE; 
  
  char* val;


  /* Allocate some tokens as a start */
  t = malloc(sizeof(*t) * tokcount);
  if (t == NULL) {
    D (("Could not allocate memory for JSON tokens\n"));
    return PAM_AUTH_ERR;
  }

  
  
  // start json parser
  jsmn_init(&p);
 parser:
  r = jsmn_parse(&p, response.payload, response.size, t, tokcount);
  if (r < 0) {
    if (r == JSMN_ERROR_NOMEM) {
      tokcount = tokcount * 2; //double token count
      t=realloc(t, sizeof(*t)*tokcount);
      if (t == NULL) {
          return PAM_ABORT;
      }
      goto parser;
    }
   return PAM_ABORT;
  }
  /* Assume the top-level element is an object */
  // ll if (r < 1 || t[0].type != JSMN_OBJECT) {
  if (r < 1 || t->type != JSMN_OBJECT) {
    D (("JSON Object expected\n"));
    return PAM_ABORT;
  }


  
  for (i = 1; i < r; i++) {
    if (jsoneq(response.payload, &t[i], key) == 0) {
      val=(char *) malloc(t[i + 1].end - t[i + 1].start);
      val = strndup(response.payload + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      *value = val;
      // skip the rest if key is found
      return 0;
    }
    i++;
  }

  // key not found?
  return PAM_ABORT;
}




static int
read_agent_conf(char* conf_file, AGENT_CONFIG *ag_conf, const struct lib_cfg cfg){
  FILE * pFile;
  long lSize;
  char * conf_buffer;
  size_t result;
  
  int r,i;
  jsmn_parser p;
  jsmntok_t t[20]; /* We expect no more than 6 tokens by definition */


  ag_conf->dev_auth_url=NULL;
  ag_conf->token_url=NULL;
  ag_conf->client_id=NULL;
  ag_conf->client_secret=NULL;
  ag_conf->client_scopes=NULL;
  ag_conf->ca_certs=NULL;

  
  pFile = fopen (conf_file, "rb");
  if (pFile==NULL) {DBG (("Agent conf file missing\n")); return 1;}
  // conf file size:
  fseek (pFile , 0 , SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);
  // allocate memory to contain the whole file:
  conf_buffer = (char*) malloc (sizeof(char)*lSize);
  if (conf_buffer == NULL) {DBG (("Cannot allocate mem for agent conf")); return 1;}
  // copy conf file into the mem:
  result = fread (conf_buffer,1,lSize,pFile);
  if (result != lSize) {DBG (("Reading agent conf error")); return 1;}

  // start json parser
  jsmn_init(&p);
  r = jsmn_parse(&p, conf_buffer, lSize, t, sizeof(t) / sizeof(t[0]));
  if (r < 0) {
    DBG (("Failed to parse JSON agent conf: %d\n", r));
    return 1;
  }
  /* Assume the top-level element is an object */
  // ll  if (r < 1 || t[0].type != JSMN_OBJECT) {
  if (r < 1 || t->type != JSMN_OBJECT) {
    DBG (("JSON Object expected in conf file\n"));
    return 1;
  }


  
  for (i = 1; i < r; i++) {
    if (jsoneq(conf_buffer, &t[i], "dev_auth_url") == 0) {
      ag_conf->dev_auth_url=(char *) malloc(t[i + 1].end - t[i + 1].start);
      ag_conf->dev_auth_url = strndup(conf_buffer + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      DBG(("Digesting ag_conf->dev_auth_url %s",ag_conf->dev_auth_url));
      i++;
    } else if (jsoneq(conf_buffer, &t[i], "token_url") == 0) {
      ag_conf->token_url=(char *) malloc(t[i + 1].end - t[i + 1].start);
      ag_conf->token_url = strndup(conf_buffer + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      DBG(("Digesting ag_conf->token_url %s",ag_conf->token_url));
      i++;
    } else if (jsoneq(conf_buffer, &t[i], "client_id") == 0) {
      ag_conf->client_id=(char *) malloc(t[i + 1].end - t[i + 1].start);
      ag_conf->client_id = strndup(conf_buffer + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      DBG(("Digesting ag_conf->client_id %s",ag_conf->client_id));
      i++;
    } else if (jsoneq(conf_buffer, &t[i], "client_secret") == 0) {
      ag_conf->client_secret=(char *) malloc(t[i + 1].end - t[i + 1].start);
      ag_conf->client_secret = strndup(conf_buffer + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      DBG(("Digesting ag_conf->client_secret %s",ag_conf->client_secret));
      i++;
    } else if (jsoneq(conf_buffer, &t[i], "client_scopes") == 0) {
      ag_conf->client_scopes=(char *) malloc(t[i + 1].end - t[i + 1].start);
      ag_conf->client_scopes = strndup(conf_buffer + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      DBG(("Digesting ag_conf->client_scopes %s",ag_conf->client_scopes));
      i++;
    } else if (jsoneq(conf_buffer, &t[i], "ca_certs") == 0) {
      ag_conf->ca_certs=(char *) malloc(t[i + 1].end - t[i + 1].start);
      ag_conf->ca_certs = strndup(conf_buffer + t[i + 1].start,t[i + 1].end - t[i + 1].start);
      DBG(("Digesting ag_conf->ca_certs %s",ag_conf->ca_certs));
      i++;
    } else {
      DBG (("Unexpected key: %.*s\n", t[i].end - t[i].start,conf_buffer + t[i].start));
      return 1;
    }
  }

  if (!ag_conf->dev_auth_url || !ag_conf->token_url || !ag_conf->client_id ||
      !ag_conf->client_secret || !ag_conf->client_scopes || !ag_conf->ca_certs ){
    DBG (("Missing configuration item"));
    return 1;
  }
    
  // terminate
  fclose (pFile);
  free (conf_buffer);
  
    
  return 0;
}




static char *
decode_base64 (const char *b64input,int nbytes, const struct lib_cfg cfg){


  BIO  *mem, *b64;
  char *base64_decoded;

  DBG(("B64 decoding this\n%s\n",b64input));
  
  // JWT uses Base64Url encoding, which does not require padding.
  char sanitized_b64input[nbytes+10];
  int r=nbytes%4;
  strcpy(sanitized_b64input, b64input);
  if (r == 3){
    strcat(sanitized_b64input, "=");
  }else if (r == 2 ){
    strcat(sanitized_b64input, "==");
  }
  int sanitized_nbytes = strlen(sanitized_b64input);
  //
  
  base64_decoded = calloc( (sanitized_nbytes*B64CONV_FACTOR)+1, sizeof(char) );
  b64 = BIO_new(BIO_f_base64());
  mem = BIO_new(BIO_s_mem());
  BIO_write(mem, sanitized_b64input, sanitized_nbytes);
  BIO_push(b64, mem);
  BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);


  // loop over bytes
  int byte_index = FALSE;
  while ( FALSE < BIO_read(b64, base64_decoded+byte_index, TRUE) ){
    byte_index++;
  }

  DBG(("..into this:\n%s\n",base64_decoded));
  
  BIO_free_all(b64);

  
  return base64_decoded;

}

static size_t
c_write_callback(char *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  C_FETCH  *mem = (C_FETCH *)userp;

  char * old_payload = mem->payload;
  mem->payload = (char*)realloc(old_payload, mem->size + realsize + 1);

  if(!mem->payload) {
    // out of memory, clean up and return
    if (old_payload){free(old_payload);}
    mem->size = 0; 
    return (size_t) -1;
  }

  
  memcpy(mem->payload+mem->size, contents, realsize);
  mem->size += realsize;
  mem->payload[mem->size] = 0;

  return realsize;
}


static int
c_do_post(char * url, char * data, C_FETCH *c_fetcher, const struct lib_cfg cfg) {
  int r;
  
  // initiate a curl session
  CURL *c_curl;

  
  // init arbitrary small
  c_fetcher->payload = malloc((size_t) INIT_SIZE);  
  c_fetcher->size = 0;    

  
  c_curl = curl_easy_init();

  DBG(("POSTing %s\nto %s\n",data,url));
  
  if  (c_curl) {
    curl_easy_setopt(c_curl, CURLOPT_WRITEFUNCTION, c_write_callback);
    curl_easy_setopt(c_curl, CURLOPT_WRITEDATA,(void*)c_fetcher);
    curl_easy_setopt(c_curl, CURLOPT_URL, url) ;
    curl_easy_setopt(c_curl, CURLOPT_POST, TRUE); 
    curl_easy_setopt(c_curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(c_curl, CURLOPT_USERAGENT, AGENT);
    r = curl_easy_perform(c_curl);
    curl_easy_cleanup(c_curl);
    return r == CURLE_OK ? CURLE_OK : CURLE_REMOTE_ACCESS_DENIED;
  } else {
    DBG(("Failed to execute POST to server\n"));
    return CURLE_REMOTE_ACCESS_DENIED; 
  }
}

static int
display_pam_info_unbuffered(pam_handle_t *pamh, char* prompt_message) {
        int retval;
	const void *item;
	const struct pam_conv *conv;
        struct pam_message msg;
	const struct pam_message *msgs[1];
        struct pam_response *resp;


        if ((retval = pam_get_item( pamh, PAM_CONV, &item)) != PAM_SUCCESS)
	  return retval;
	

	conv = (const struct pam_conv *)item;
        msg.msg_style = PAM_TEXT_INFO;
        msg.msg = prompt_message;
	msgs[0] = &msg;


	if ((retval = conv->conv( 1, msgs, &resp, conv->appdata_ptr )) != PAM_SUCCESS)
	  return retval;


	free(resp);
        return PAM_SUCCESS;
}

extern char * make_qr(char* str);

// expected hooks

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  int res;
  struct lib_cfg cfg;
    
  const char *user;
  const struct passwd *pwd_entry;

  pid_t useradd_pid, w;
  int status;



  parse_lib_cfg(flags, argc, argv, &cfg);

  
  res = pam_get_user(pamh, &user, NULL);
  if (res != PAM_SUCCESS){
    DBG (("Cannot get user"));
    return res;
  }
  
  pwd_entry = getpwnam(user);
  if (!pwd_entry)
    {
      DBG(("User %s not found..creating it",user));

      useradd_pid = fork();
      if (useradd_pid == -1) {
        DBG(("Unable to fork useradd process"));
	return PAM_SESSION_ERR;
      }

      if (useradd_pid == 0) {
	// useradd
	DBG(("Trying adding user %s to system",user));
	char *useradd_argv[6] = {"","useradd","-m", "-U ", (char*)user,NULL};
	res=execve(ECHO, useradd_argv,NULL);
	if (res == -1){
	  DBG(("execve terminated unsuccessfully"));
	  exit(EXIT_FAILURE);
	}
      }

      w = waitpid(useradd_pid, &status,FALSE);
      if (w == -1) {
	DBG(("Wait for useradd terminated unsuccessfully"));
	return PAM_SESSION_ERR;
      }

      if (WIFEXITED(status) && !WEXITSTATUS(status)) {
	DBG(("Useradd terminated successfully"));
	// useradd is done successfully
	return PAM_SUCCESS;
      }

      // useradd failed for some reason
      DBG(("Error: could not add user %s to system",user));
      return PAM_SESSION_ERR;
    }

  // no need to add user
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

// auth hook
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv) {

  int t;
  int res;
  char* post_data;
  int post_r;
	
  const void *pamuser;

  char* usercode=NULL;
  char *devicecode=NULL;
  char* loginurl=NULL;

  char* idtoken=NULL;
  char* errormsg=NULL;
  char* username=NULL;

  size_t tmpl_len;
  char* prompt_message=NULL;
  
  C_FETCH c_fetcher;
  AGENT_CONFIG ag_conf;
  struct lib_cfg cfg;


  
  // read lib cmdline options
  parse_lib_cfg(flags, argc, argv, &cfg);


  // read agent configuration file
  if (read_agent_conf(cfg.agentconf, &ag_conf, cfg) != 0){
    DBG(("Failed to parse JSON agent conf: %s or item missing from it.\n", cfg.agentconf));
    return PAM_AUTH_ERR;
  }


  // call this 1 time only
  curl_global_init(CURL_GLOBAL_ALL);
	

  // build POST request body for authorization
  post_data=make_auth_request_body(ag_conf);



  // execute POST
  if (post_r = c_do_post(ag_conf.dev_auth_url, post_data, &c_fetcher,cfg))
    return post_r;
  free(post_data);

	
  // response contains user_code and device_code; read them
  read_json_response_dynamic(c_fetcher,KC_USERCODE_KEY,&usercode);
  read_json_response_dynamic(c_fetcher,KC_DEVICECODE_KEY,&devicecode);
  read_json_response_dynamic(c_fetcher,KC_VERIFICATION_URI_KEY,&loginurl);
  free(c_fetcher.payload);

  // quick check
  if (!usercode || !devicecode || !loginurl){
    DBG (("Could not retrieve %s from authentication server\n",KC_USERCODE_KEY));
    goto failure;
  }
	  
  
  if (cfg.qrcode){
    char* qrc = make_qr(loginurl);

    const char *prompt_tmpl="\n\nTo continue, login to\n\n\t%s\n\nor scan the QR code below\n\n%s";
	  
    tmpl_len=snprintf(NULL,0,prompt_tmpl,loginurl,qrc);
    prompt_message = malloc(tmpl_len+1);
	  
    sprintf(prompt_message, prompt_tmpl,loginurl,qrc );

	  
    if (!prompt_message){
      free(qrc);
      return PAM_BUF_ERR;
    }
    free(qrc);
  } else {
    const char *prompt_tmpl = "\n\nTo continue, login to\n\n\t%s\n\n";

    
    tmpl_len=snprintf(NULL,0,prompt_tmpl,loginurl);
    prompt_message = malloc(tmpl_len+1);
    sprintf(prompt_message, prompt_tmpl,loginurl);

    if (!prompt_message){
      return PAM_BUF_ERR;
    }
  }


	
  // work around SSH PAM bug that buffers PAM_TEXT_INFO until end auth
  // use this if no buffer problems

  pam_prompt(pamh, PAM_TEXT_INFO, NULL, prompt_message);
  free(prompt_message);
  // use this with buffer problems
  //display_pam_info_unbuffered(pamh, prompt_message);
	
	

  char *resp;
  res = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "Once you have completed the login process, press Enter");
  DBG (("User entered: %s\n",resp));
  free(resp);

  // build POST request body for token
  post_data=make_token_request_body(ag_conf,devicecode);

  // once user pushes enter, try requesting token periodically
  // (polling) and fail auth after timeout
  for(t=TOKEN_REQUEST_TIMEOUT; t>=0; t-=TOKEN_REQUEST_TIME_STEP) {

    DBG (("Seconds left to complete authentication: %d",t));
    c_do_post(ag_conf.token_url, post_data, &c_fetcher,cfg);

    read_json_response_dynamic(c_fetcher,KC_ERROR_KEY,&errormsg);

    
    // user successfully authenticated on the server
    if (!errormsg) {

      //get the idtoken = header.payload.signature
      read_json_response_dynamic(c_fetcher,KC_IDTOKEN_KEY,&idtoken);
			
      // jwtk signature ignored			
      char* header = strtok(idtoken, JWT_SEPARATOR);
      char* payload = strtok(NULL, JWT_SEPARATOR);
			
      char* decoded = decode_base64(payload,strlen(payload), cfg);
			
			
      C_FETCH decoded_payload_struct;
      decoded_payload_struct.payload = decoded;
      decoded_payload_struct.size = strlen(decoded);
      read_json_response_dynamic(decoded_payload_struct,KC_USERNAME_KEY,&username);

			
			
      int  pgi_err = pam_get_item(pamh, PAM_USER, &pamuser);
      if (pgi_err!=PAM_SUCCESS){
	 DBG (("Cannot define PAM user"));
	 goto failure;
      }
	
      // pam user matches username in tokenid
      if (strcmp(pamuser, username) == 0){

	DBG (("Authenticated user %s matches with PAM user %s",username,pamuser));

	free(usercode);
	free(devicecode);
	free(loginurl);

	curl_global_cleanup();
	if (c_fetcher.payload)
	  free(c_fetcher.payload);
	free(ag_conf.dev_auth_url);
	free(ag_conf.token_url);
	free(ag_conf.client_id);
	free(ag_conf.client_secret);
	free(ag_conf.client_scopes);
	free(ag_conf.ca_certs);

	DBG_WRN
	return PAM_SUCCESS;
      }

      // pam user does NOT matche username in tokenid
      DBG (("\n\nYou are NOT who you claim to be\n\n", username, pamuser));
      goto failure;

    }

    //auth server returned an error message when requesting an idtoken
    DBG (("Authentication failure; %s\n", errormsg));
    // wait, perhaps the user needs more time to authenticate
    sleep(TOKEN_REQUEST_TIME_STEP);
		
  }

  // at this point timeout is reached: clean up and fail
 failure:
  free(usercode);
  free(devicecode);
  free(loginurl);
  
  curl_global_cleanup();
  if (c_fetcher.payload)
    free(c_fetcher.payload);
  free(ag_conf.dev_auth_url);
  free(ag_conf.token_url);
  free(ag_conf.client_id);
  free(ag_conf.client_secret);
  free(ag_conf.client_scopes);
  free(ag_conf.ca_certs);


  DBG_WRN

  return PAM_AUTH_ERR;
}
	
