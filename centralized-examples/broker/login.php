<?php
use Jasny\SSO\NotAttachedException;
require_once __DIR__ . '/../../vendor/autoload.php';

$broker = new Jasny\SSO\Broker(getenv('SSO_SERVER'), getenv('SSO_BROKER_ID'), getenv('SSO_BROKER_SECRET'));
$broker->attach(true);

try {
    if (!empty($_GET['logout'])) {
        $broker->logout();
        header("Location: index.php", true);
    } elseif ($broker->getUserInfo()) {
        header("Location: profile.php", true);
    } else {
        header('Location: ' . 'http://localhost:9000/login.php?redirect_url=http://localhost:9002/login.php'.'&access_token='.$broker->getSessionId());
    }

} catch (NotAttachedException $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (Jasny\SSO\Exception $e) {
    $errmsg = $e->getMessage();
}

