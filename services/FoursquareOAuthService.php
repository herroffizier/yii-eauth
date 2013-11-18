<?php
/**
 * FoursquareOAuthService class file.
 *
 * Register application: https://foursquare.com/developers/register
 *
 * @author Martin Stolz <herr.offizier@gmail.com>
 * @link http://github.com/Nodge/yii-eauth/
 * @license http://www.opensource.org/licenses/bsd-license.php
 */

require_once dirname(dirname(__FILE__)) . '/EOAuth2Service.php';

/**
 * Foursquare provider class.
 *
 * @package application.extensions.eauth.services
 */
class FoursquareOAuthService extends EOAuth2Service {

    protected $name = 'foursquare';
    protected $title = 'Foursquare';
    protected $type = 'OAuth';
    protected $jsArguments = array('popup' => array('width' => 700, 'height' => 350));

    protected $client_id = '';
    protected $client_secret = '';

    protected $providerOptions = array(
        'authorize' => 'https://foursquare.com/oauth2/authenticate',
        'access_token' => 'https://foursquare.com/oauth2/access_token',
    );

    protected $id = null;

    /**
     * Version parameter required by API.
     * By default sets to current date which may be bad practice.
     * @see https://developer.foursquare.com/overview/versioning
     * 
     * @var string
     */
    protected $version = null;

    public function init($component, $options = array())
    {
        parent::init($component, $options);

        if ($this->version === null) {
            $this->version = date('Ymd');
        }
    }

    protected function fetchAttributes() {
        $user = null;

        $data = $this->makeSignedRequest('https://api.foursquare.com/v2/users/self', array());
        if (isset($data->response) && isset($data->response->user)) {
            $user = $data->response->user;
        }

        if ($user) {
            $this->attributes['id'] = $user->id;
            $this->attributes['name'] = $user->firstName.' '.$user->lastName;
            $this->attributes['url'] = 'https://foursquare.com/user/'.$user->id;
        }
    }

    /**
     * Returns the url to request to get OAuth2 code.
     *
     * @param string $redirect_uri url to redirect after user confirmation.
     * @return string url to request.
     */
    protected function getCodeUrl($redirect_uri) {
        $this->setState('redirect_uri', $redirect_uri);

        $url = parent::getCodeUrl($redirect_uri);

        return $url;
    }

    /**
     * Returns the url to request to get OAuth2 access token.
     *
     * @param string $code
     * @return string url to request.
     */
    protected function getTokenUrl($code) {
        return $this->providerOptions['access_token'].'?'.http_build_query(array(
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getState('redirect_uri'),
            'code' => $code,
        ));
    }

    /**
     * Returns the OAuth2 access token.
     *
     * @param string $code the OAuth2 code. See {@link getCodeUrl}.
     * @return string the token.
     */
    protected function getAccessToken($code) {
        return $this->makeRequest($this->getTokenUrl($code));
    }

    /**
     * Save access token to the session.
     *
     * @param stdClass $token access token object.
     */
    protected function saveAccessToken($token) {
        $this->access_token = $token->access_token;
        $this->id = $this->getId();

        $this->setState('auth_token', $token->access_token);
        $this->setState('id', $this->getId());
        $this->setState('expires', time() * 2);
    }

    /**
     * Restore access token from the session.
     *
     * @return boolean whether the access token was successfuly restored.
     */
    protected function restoreAccessToken() {
        if ($this->hasState('id') && parent::restoreAccessToken()) {
            $this->id = $this->getState('id');
            return true;
        }
        else {
            $this->id = null;
            return false;
        }
    }

    /**
     * Returns the error info from json.
     *
     * @param stdClass $json the json response.
     * @return array the error array with 2 keys: code and message. Should be null if no errors.
     */
    protected function fetchJsonError($json) {
        if (isset($json->meta) && isset($json->meta->errorDetail)) {
            return array(
                'code' => $json->meta->code ?: 0,
                'message' => $json->meta->errorDetail ?: '',
            );
        }
        else {
            return null;
        }
    }

    protected function getSignedRequestFields()
    {
        return array(
            'oauth_token' => $this->access_token,
            'v' => $this->version,
        );
    }

}