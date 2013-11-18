<?php
/**
 * InstagramOAuthService class file.
 *
 * Register application: http://instagram.com/developer/clients/manage/
 *
 * @author Martin Stolz <herr.offizier@gmail.com>
 * @link http://github.com/Nodge/yii-eauth/
 * @license http://www.opensource.org/licenses/bsd-license.php
 */

require_once dirname(dirname(__FILE__)) . '/EOAuth2Service.php';

/**
 * Instagram provider class.
 *
 * @package application.extensions.eauth.services
 */
class InstagramOAuthService extends EOAuth2Service {

    protected $name = 'instagram';
    protected $title = 'Instagram';
    protected $type = 'OAuth';
    protected $jsArguments = array('popup' => array('width' => 585, 'height' => 350));

    protected $client_id = '';
    protected $client_secret = '';
    protected $scope = 'basic';
    protected $providerOptions = array(
        'authorize' => 'https://api.instagram.com/oauth/authorize',
        'access_token' => 'https://api.instagram.com/oauth/access_token',
    );

    protected $id = null;

    /**
     * Token returned by Instagram API with user info.
     * Used in {@link fetchAttributes} only to save one request
     * to API.
     * @var stdClass
     */
    protected $rawToken = null;

    protected function fetchAttributes() {
        $user = null;

        if ($this->rawToken) {
            $user = $this->rawToken->user;
        }
        else {
            $data = $this->makeSignedRequest('https://api.instagram.com/v1/users/'.$this->id, array());
            if (isset($data->data)) {
                $user = $data->data;
            }
        }

        if ($user) {
            $this->attributes['id'] = $user->id;
            $this->attributes['name'] = $user->full_name;
            $this->attributes['url'] = 'http://instagram.com/'.$user->username;
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
        return $this->providerOptions['access_token'];
    }

    /**
     * Returns the OAuth2 access token.
     *
     * @param string $code the OAuth2 code. See {@link getCodeUrl}.
     * @return string the token.
     */
    protected function getAccessToken($code) {
        return $this->makeRequest($this->getTokenUrl($code), array('data' => array(
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getState('redirect_uri'),
            'code' => $code,
        )));
    }

    /**
     * Save access token to the session.
     *
     * @param stdClass $token access token object.
     */
    protected function saveAccessToken($token) {
        $this->rawToken = $token;
        $this->setState('auth_token', $token->access_token);
        $this->setState('id', $token->user->id);
        $this->setState('expires', time() * 2);
        $this->id = $token->user->id;
        $this->access_token = $token->access_token;
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
        if (isset($json->meta) && isset($json->meta->error_message)) {
            return array(
                'code' => $json->meta->error_code ?: 0,
                'message' => $json->meta->error_message ?: '',
            );
        }
        else {
            return null;
        }
    }
}