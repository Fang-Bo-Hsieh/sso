<?php
use Jasny\SSO\NotAttachedException;
require_once __DIR__ . '/../../vendor/autoload.php';
require_once 'MySSOServer.php';

$redirectUrl = isset($_GET['redirect_url'])?$_GET['redirect_url']:$_POST['redirect_url'];
$ssoServer = new MySSOServer();

try {
    $ssoServer->setSessionData('sso_user', null);
    // 登出成功，回導到傳來的redirect_url
    header("Location: ".$redirectUrl);
    exit();
} catch (NotAttachedException $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (Jasny\SSO\Exception $e) {
    $errmsg = $e->getMessage();
}

?>
