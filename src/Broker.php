<?php
namespace Jasny\SSO;

/**
 * Single sign-on broker.
 *
 * The broker lives on the website visited by the user. The broken doesn't have any user credentials stored. Instead it
 * will talk to the SSO server in name of the user, verifying credentials and getting user information.
 */
class Broker
{
    /**
     * Url of SSO server
     * @var string
     */
    protected $url;

    /**
     * My identifier, given by SSO provider.
     * @var string
     */
    public $broker;

    /**
     * My secret word, given by SSO provider.
     * @var string
     */
    protected $secret;

    /**
     * Session token of the client
     * @var string
     */
    public $token;

    /**
     * Sso server is alive
     * @var string
     */
    protected $isSsoSiteAlive;

    /**
     * User info recieved from the server.
     * @var array
     */
    protected $userinfo;

    /**
     * User uuid.
     * @var string
     */
    protected $uuid;

    /**
     * Cookie lifetime
     * @var int
     */
    protected $cookie_lifetime;

    /**
     * Login page path
     * @var int
     */
    protected $loginPagePath;

    /**
     * Session lifetime
     * @var int
     */
    protected $session_lifetime;

    /**
     * Class constructor
     *
     * @param string $url    Url of SSO server
     * @param string $broker My identifier, given by SSO provider.
     * @param string $secret My secret word, given by SSO provider.
     * @param string $secret My secret word, given by SSO provider.
     * @param int $cookie_lifetime cookie life time.
     * @param string $loginPagePath login uri.
     * @param int $session_lifetime session life time.
     */
    public function __construct($url, $broker, $secret, $cookie_lifetime = 86400, $loginPagePath = 'login', $session_lifetime = 86400)
    {
        if (!$url) throw new \InvalidArgumentException("SSO server URL not specified");
        if (!$broker) throw new \InvalidArgumentException("SSO broker id not specified");
        if (!$secret) throw new \InvalidArgumentException("SSO broker secret not specified");

        $this->url = $url;
        $this->broker = $broker;
        $this->secret = $secret;
        $this->cookie_lifetime = $cookie_lifetime;
        $this->loginPagePath = $loginPagePath;
        $this->session_lifetime = $session_lifetime;

        if (isset($_COOKIE[$this->getCookieName()])) $this->token = $_COOKIE[$this->getCookieName()];
    }

    /**
     * singleton pattern
     * @param $url
     * @param $broker
     * @param $secret
     * @param int $cookie_lifetime
     * @return Broker
     */
    public static function &instance($url, $broker, $secret, $cookie_lifetime = 86400)
    {
        static $instance;
        if (!$instance) {
            $instance = new self($url, $broker, $secret, $cookie_lifetime);
        }

        return $instance;
    }

    /**
     * Get the cookie name.
     *
     * Note: Using the broker name in the cookie name.
     * This resolves issues when multiple brokers are on the same domain.
     *
     * @return string
     */
    protected function getCookieName()
    {
        return 'sso_token_' . preg_replace('/[_\W]+/', '_', strtolower($this->broker));
    }

    /**
     * Generate session id from session key
     *
     * @return string
     */
    public function getSessionId()
    {
        if (!isset($this->token)) return null;

        $checksum = hash('sha256', 'session' . $this->token . $this->secret);
        return "SSO-{$this->broker}-{$this->token}-$checksum";
    }

    /**
     * Generate session token
     */
    public function generateToken()
    {
        if (isset($this->token)) return;

        $this->token = base_convert(md5(uniqid(rand(), true)), 16, 36);
        setcookie($this->getCookieName(), $this->token, time() + $this->cookie_lifetime, '/');
    }

    /**
     * Clears session token
     */
    public function clearToken()
    {
        setcookie($this->getCookieName(), null, 1, '/');

        // 確認session中uuid是否有值
        $this->userinfo = $this->getUserInfoFromSession();

        // 若session有值，登出時需要清掉
        if ($this->userinfo) {
            $this->clearUserInfoFromSession();
        }

        $this->token = null;
    }

    /**
     * Check if we have an SSO token.
     *
     * @return boolean
     */
    public function isAttached()
    {
        return isset($this->token);
    }

    /**
     * Get URL to attach session at SSO server.
     *
     * @param array $params
     * @return string
     */
    public function getAttachUrl($params = array())
    {
        $this->generateToken();

        $data = array(
            'command' => 'attach',
            'broker' => $this->broker,
            'token' => $this->token,
            'checksum' => hash('sha256', 'attach' . $this->token . $this->secret)
        );

        $data = array_merge($data, $_GET);

        return $this->url . "?" . http_build_query($data + $params);
    }

    /**
     * Attach our session to the user's session on the SSO server.
     *
     * @param string|true $returnUrl  The URL the client should be returned to after attaching
     */
    public function attach($returnUrl = null)
    {
        if ($this->isAttached()) return;

        if ($returnUrl === true) {
            $protocol = !empty($_SERVER['HTTPS']) ? 'https://' : 'http://';
            $returnUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        }

        // 確認server狀態，若sso server掛掉，則不進行交互，確保平台網站正常運作
        if (!$this->checkSsoSiteAlive($this->url.'/nginx-health')) {
            return;
        }

        $params = array('return_url' => $returnUrl);
        $url = $this->getAttachUrl($params);

//        exit($url);
        header("Location: $url", true, 307);
        echo "You're redirected to <a href='$url'>$url</a>";
        exit();
    }

    /**
     * Get the request url for a command
     *
     * @param string $command
     * @param array  $params   Query parameters
     * @return string
     */
    protected function getRequestUrl($command, $params = array())
    {
        $params['command'] = $command;
        return $this->url . '?' . http_build_query($params);
    }

    /**
     * 請求 SSO server API
     *
     * @param string       $method  HTTP method: 'GET', 'POST', 'DELETE'
     * @param string       $command Command
     * @param array|string $data    Query or post parameters
     *
     * @throws NotAttachedException | Exception
     * @return array|object
     */
    protected function request($method, $command, $data = null)
    {
        if (!$this->isAttached()) {
            throw new NotAttachedException('No token');
        }
        $url = $this->getRequestUrl($command, !$data || $method === 'POST' ? array() : $data);

        $ch = curl_init($url);

        // 若url有帶https
        $SSL = substr($url, 0, 8) == "https://" ? true : false;
        if ($SSL) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);   // 只信任CA頒布的證書
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2); // 检查證書中是否設置域名，並且是否與主機名匹配
        }

        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT , 15);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); //timeout in seconds
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_VERBOSE, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json', 'Sso-Authorization: Bearer ' . $this->getSessionId()));

        if ($method === 'POST' && !empty($data)) {
            $post = is_string($data) ? $data : http_build_query($data);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        }

        $response = curl_exec($ch);
//        exit(json_encode($response));

        //Something to write to txt log
//        $log  = "response = " . json_encode($response).'\n';;
//        //Save string to log, use FILE_APPEND to append.
//        file_put_contents('./broker-log_'.date("j.n.Y").'.txt', $log, FILE_APPEND);

        if (curl_errno($ch) != 0) {
            $message = 'Server request failed: ' . curl_error($ch);
            throw new Exception($message);
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        list($contentType) = explode(';', curl_getinfo($ch, CURLINFO_CONTENT_TYPE));

        if ($contentType != 'application/json') {
            $message = 'Expected application/json response, got ' . $contentType;
            throw new Exception($message);
        }

        $data = json_decode($response, true);
        if ($httpCode == 403) {
            $this->clearToken();
            throw new NotAttachedException($data['error'] ?: $response, $httpCode);
        }
        if ($httpCode >= 400) throw new Exception($data['error'] ?: $response, $httpCode);

        return $data;
    }


    /**
     * Login the client at the SSO server. (透過API進行登入時才使用)
     *
     * Only brokers marked trused can collect and send the user's credentials. Other brokers should omit $username and
     * $password.
     *
     * @param string $username
     * @param string $password
     * @return array  user info
     * @throws Exception if login fails eg due to incorrect credentials
     */
    public function login($username = null, $password = null)
    {
        if (!isset($username) && isset($_POST['username'])) $username = $_POST['username'];
        if (!isset($password) && isset($_POST['password'])) $password = $_POST['password'];

        $result = $this->request('POST', 'login', compact('username', 'password'));
        $this->userinfo = $result;

        return $this->userinfo;
    }

    /**
     * Logout at sso server. (透過API進行登出時才使用)
     */
    public function logout()
    {
        $this->request('GET', 'logout');
    }

    /**
     * Get user information.
     *
     * @param string $sso_user_id
     *
     * @return object|null
     */
    public function getUserInfo($sso_user_id = null)
    {
        // 服務器暫存
        $this->userinfo = $this->getUserInfoFromSession();

        if (!isset($this->userinfo) || !$this->userinfo) {
            // 透過API從sso server獲取用戶資料
            $this->userinfo = $this->request('GET', 'userInfo', is_null($sso_user_id)?null:array('sso_user_id' => $sso_user_id));

            // 用uuid作為key值
            if (isset($this->userinfo['uuid']) && $this->userinfo['uuid']) {
                // 將結果暫存在session中，n小时後過期
                $this->uuid = $this->userinfo['uuid'];
                $this->saveUuidToSession($this->uuid);
                $this->saveUserInfoToSession($this->userinfo);
            }
        }

        return $this->userinfo;

    }

    /**
     * Update user information which store in session.
     *
     * @param $userInfoArray
     * @return object|null
     */
    public function updateUserInfoToSession($userInfoArray)
    {
        $this->userinfo = $this->getUserInfoFromSession();
        if (!isset($this->userinfo) || !$this->userinfo) {
            return false;
        }

        $this->userinfo = $userInfoArray;
        $this->uuid = $userInfoArray['uuid'];
        // 將session中的值更新
        $_SESSION[$this->uuid] = json_encode($userInfoArray);

        return $this->userinfo;
    }

    /**
     * Encode token string
     *
     * @return string
     */
    public function encode($string, $key) {
//        $hash = '';
//        $hash = sha1($key);
//        $strLen = strlen($string);
//        $keyLen = strlen($key);
//        $j = 0;
//        for ($i = 0; $i < $strLen; $i++) {
//            $ordStr = ord(substr($string,$i,1));
//            if ($j == $keyLen) { $j = 0; }
//            $ordKey = ord(substr($key,$j,1));
//            $j++;
//            $hash .= strrev(base_convert(dechex($ordStr + $ordKey),16,36));
//        }

        return str_replace(array('+', '/'), array('-', '_'), base64_encode($string));
    }

    /**
     * Magic method to do arbitrary request
     *
     * @param string $fn
     * @param array  $args
     * @return mixed
     */
    public function __call($fn, $args)
    {
        $sentence = strtolower(preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $fn));
        $parts = explode(' ', $sentence);

        $method = count($parts) > 1 && in_array(strtoupper($parts[0]), array('GET', 'DELETE'))
            ? strtoupper(array_shift($parts))
            : 'POST';
        $command = join('-', $parts);

        return $this->request($method, $command, $args);
    }

    /**
     * 檢查網站是否能存活
     * @param string $url
     * @return boolean
     */
    public function checkSsoSiteAlive($url)
    {
        $curl = curl_init($url);

        $SSL = substr($url, 0, 8) == "https://" ? true : false;
        if ($SSL) {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);   // 只信任CA颁布的证书
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2); // 检查证书中是否设置域名，并且是否与提供的主机名匹配
        }

        curl_setopt($curl,CURLOPT_CONNECTTIMEOUT,5);
        curl_setopt($curl,CURLOPT_HEADER,true);
        curl_setopt($curl,CURLOPT_NOBODY,true);
        curl_setopt($curl,CURLOPT_RETURNTRANSFER,true);
        $result = curl_exec($curl);
        if ($result !== false) {
            $statusCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            if ($statusCode == 404) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }


    /**
     * 從session中取得用戶在iot的資料
     * @return null
     */
    public function getUserInfoFromSession()
    {
        // 確認session中uuid是否有值
        $this->uuid = $this->getUuidFromSession();

        // 若session有值，直接從session拿
        if ($this->uuid && isset($_SESSION[$this->uuid]) && $_SESSION[$this->uuid]) {
            return json_decode($_SESSION[$this->uuid]);
        }

        return NULL;
    }

    /**
     * 從session中取得用戶在iot的uuid
     * @return null
     */
    public function getUuidFromSession()
    {
        if(!isset($_SESSION))
        {
            // 把 session 的生命週期調到你想要的時間
            ini_set('session.gc_maxlifetime', $this->session_lifetime);
            session_start();
        }

        if (isset($_SESSION['uuid']) && $_SESSION['uuid']) {
            return $_SESSION['uuid'];
        }

        return NULL;
    }

    /**
     * 清除在session中用戶iot的資料
     */
    public function clearUserInfoFromSession()
    {
        unset($_SESSION['uuid']);
        unset($_SESSION[$this->uuid]);
        $this->uuid = null;
        $this->userinfo = null;
    }

    private function saveUuidToSession($uuid)
    {
        $_SESSION['uuid'] = $uuid;
    }

    private function saveUserInfoToSession($userinfo)
    {
        $_SESSION[$this->uuid] = json_encode($userinfo);
    }
}
