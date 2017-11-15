<?php
use Jasny\SSO\NotAttachedException;
require_once __DIR__ . '/../../vendor/autoload.php';

$config = include('config.php');
$broker = new Jasny\SSO\Broker(getenv('SSO_SERVER'), getenv('SSO_BROKER_ID'), getenv('SSO_BROKER_SECRET'));
$broker->attach(true);
$currentLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
$indexUrl = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]/index.php";
$sessionId = $broker->getSessionId();

try {
    if (!empty($_GET['logout'])) {
//        $broker->logout();
//        header("Location: index.php", truhttp://localhost:9001/login.php);
        $broker->clearToken();
        header('Location: ' . getenv('SSO_SERVER').'/logout?redirect_url='.$indexUrl);
    } elseif ($broker->getUserInfo()) {
        header("Location: profile.php", true);
    } else {
        // 轉跳到sso server的login.php
        //Encryption
        $encoded = $broker->encode($sessionId, 'sso-');
        $params = [
                'redirect_url' => $currentLink,
                'bid' => $encoded,
            ];

        $url = getenv('SSO_SERVER').'/login.php?'.http_build_query($params);
        header('Location: ' . $url);
    }

} catch (NotAttachedException $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (Jasny\SSO\Exception $e) {
    $errmsg = $e->getMessage();
    echo $errmsg;
}