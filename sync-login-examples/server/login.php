<?php
use Jasny\SSO\NotAttachedException;
require_once __DIR__ . '/../../vendor/autoload.php';
require_once 'MySSOServer.php';

$redirectUrl = isset($_GET['redirect_url'])?$_GET['redirect_url']:$_POST['redirect_url'];
$ssoServer = new MySSOServer();
$username = $ssoServer->getSessionData('sso_user');

try {
    if ($ssoServer->getUserInfo($username) ||
        ($_SERVER['REQUEST_METHOD'] == 'POST' && $ssoServer->localLogin())) {
        // 登入成功，回導到傳來的redirect_url
        header("Location: ".$redirectUrl);
        exit();
    }

    // 登入失敗
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $errmsg = "Login failed";
        header('Location: ' . $_SERVER['HTTP_REFERER'].'?'.$_SERVER['QUERY_STRING'].'&errmsg='.$errmsg);
    }

    if (!empty($_GET['errmsg'])) {
        $errmsg = $_GET['errmsg'];
    }
} catch (NotAttachedException $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (Jasny\SSO\Exception $e) {
    $errmsg = $e->getMessage();
}

?>
<!doctype html>
<html>
    <head>
        <title>Centralize Login (Single Sign-On demo)</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" rel="stylesheet">

        <style>
            h1 {
                margin-bottom: 30px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1><small>(Centralize Single Sign-On demo)</small></h1>

            <?php if (isset($errmsg)): ?><div class="alert alert-danger"><?= $errmsg ?></div><?php endif; ?>

            <form class="form-horizontal" action="login.php" method="post">
                <input type="hidden" name="access_token" value="<?= $_GET['access_token'] ?>">
                <input type="hidden" name="redirect_url" value="<?= $redirectUrl ?>">
                <div class="form-group">
                    <label for="inputUsername" class="col-sm-2 control-label">Username</label>
                    <div class="col-sm-10">
                        <input type="text" name="username" class="form-control" id="inputUsername">
                    </div>
                </div>
                <div class="form-group">
                    <label for="inputPassword" class="col-sm-2 control-label">Password</label>
                    <div class="col-sm-10">
                        <input type="password" name="password" class="form-control" id="inputPassword">
                    </div>
                </div>

                <div class="form-group">
                    <div class="col-sm-offset-2 col-sm-10">
                        <button type="submit" class="btn btn-default">Login</button>
                    </div>
                </div>
            </form>
        </div>
    </body>
</html>
