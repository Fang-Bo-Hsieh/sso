<?php
use Jasny\SSO\NotAttachedException;
require_once __DIR__ . '/../../vendor/autoload.php';

$config = include('config.php');
$broker = new Jasny\SSO\Broker(getenv('SSO_SERVER'), getenv('SSO_BROKER_ID'), getenv('SSO_BROKER_SECRET'));
$broker->attach(true);
$currentLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
$sessionId = $broker->getSessionId();

try {
    if (!empty($_GET['logout'])) {
        $broker->logout();
        header("Location: index.php", true);
    } elseif ($broker->getUserInfo()) {
        header("Location: profile.php", true);
    } else {
        // 轉跳到sso server的login.php
        header('Location: ' . getenv('SSO_SERVER').'/login.php?redirect_url='.$currentLink.'&access_token='.$sessionId);
    }

} catch (NotAttachedException $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (Jasny\SSO\Exception $e) {
    $errmsg = $e->getMessage();
    echo $errmsg;
}

