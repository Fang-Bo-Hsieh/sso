<?php
require_once __DIR__ . '/../../src/Broker.php';
require_once __DIR__ . '/../../src/Exception.php';
require_once __DIR__ . '/../../src/NotAttachedException.php';

use Jasny\SSO\Broker;
use Jasny\SSO\NotAttachedException;

$config = include('config.php');
$broker = new Broker($config['SSO_SERVER'], $config['SSO_BROKER_ID'], $config['SSO_BROKER_SECRET']);
//exit('123');
$broker->attach(true);
$currentLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
$indexUrl = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]/index.php";
$sessionId = $broker->getSessionId();

try {
    if (!empty($_GET['logout'])) {
//        $broker->logout();
//        header("Location: index.php", truhttp://localhost:9001/login.php);
        $broker->clearToken();
        header('Location: ' . $config['SSO_SERVER'].'/logout?redirect_url='.$indexUrl);
    } elseif ($broker->getUserInfo()) {
        header("Location: profile.php", true);
    } else {
        // 轉跳到sso server的login.php
        //Encryption
        $encoded = $broker->encode($sessionId, 'sso-');
//        exit($encoded);
        $params = [
                'redirect_url' => $currentLink,
                'token' => $sessionId,
                'bid' => $encoded,
            ];

        $url = $config['SSO_SERVER'].'/login.php?'.http_build_query($params);
        header('Location: ' . $url);
    }

} catch (NotAttachedException $e) {
//    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit('NotAttachedException');
} catch (Jasny\SSO\Exception $e) {
    $errmsg = $e->getMessage();
    exit($errmsg);
}