<?php
use Jasny\SSO\NotAttachedException;
use Jasny\SSO\Exception as SsoException;

require_once __DIR__ . '/../../vendor/autoload.php';

if (isset($_GET['sso_error'])) {
    header("Location: error.php?sso_error=" . $_GET['sso_error'], true, 307);
    exit;
}

$broker = new Jasny\SSO\Broker(getenv('SSO_SERVER'), getenv('SSO_BROKER_ID'), getenv('SSO_BROKER_SECRET'));
$broker->attach(true);

try {
    $user = $broker->getUserInfo();
} catch (NotAttachedException $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (SsoException $e) {
    header("Location: error.php?sso_error=" . $e->getMessage(), true, 307);
}

if (!$user) {
    header("Location: index.php", true, 307);
    exit;
}
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
            <h3>Logged in</h3>

            <pre><?= json_encode($user, JSON_PRETTY_PRINT); ?></pre>

<!--            <form id="logout-form" class="form-horizontal" action="--><?//= getenv('SSO_SERVER').'/logout' ?><!--" method="post">-->
<!--                <input type="hidden" name="redirect_url" value="localhost:9001/index.php">-->
<!--                <a href="javascript:void(0)" class="btn btn-default"-->
<!--                   onclick="document.getElementById('logout-form').submit(); return false;">Logout</a>-->
<!--            </form>-->
            <a id="logout" class="btn btn-default" href="login.php?logout=1">Logout</a>
        </div>
    </body>
</html>

