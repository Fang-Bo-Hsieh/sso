<?php
use Jasny\SSO\NotAttachedException;
use Jasny\SSO\Exception as SsoException;

require_once __DIR__ . '/../../vendor/autoload.php';

if (isset($_GET['sso_error'])) {
    header("Location: error.php?sso_error=" . $_GET['sso_error'], true, 307);
    exit;
}

$config = include('config.php');
$broker = new Jasny\SSO\Broker(getenv('SSO_SERVER'), getenv('SSO_BROKER_ID'), getenv('SSO_BROKER_SECRET'));
// 將client的資訊透過broker傳給sso server
$broker->attach(true);

?>
<!doctype html>
<html>
    <head>
        <title><?= $broker->broker ?> (Single Sign-On demo)</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1><?= $broker->broker ?> <small>(Single Sign-On demo)</small></h1>
            <a id="login" class="btn btn-default" href="login.php?test=1">點我登入</a>
        </div>
    </body>
</html>

