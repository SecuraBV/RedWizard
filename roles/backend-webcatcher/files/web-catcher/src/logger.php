<?php
    $record = TRUE; // whether or not to record requests

    header('HTTP/1.1 200 OK', TRUE, 200);

    if($record) {
        // Get remote IP
        // If the site uses cloudflare, the true remote IP is served
        // in the HTTP_CF_CONNECTING_IP server var:
        $ip = isset($_SERVER['HTTP_CF_CONNECTING_IP'])
            ? $_SERVER['HTTP_CF_CONNECTING_IP']
            : $_SERVER['REMOTE_ADDR'];

        ob_start();

        // Request date / IP / URL
        echo date('Y-m-d H:i:s: ')
            . 'Remote IP: ' . $ip
            . ' - ' . $_SERVER['REQUEST_METHOD']
            . ' ' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']
            . "\r\n";

        // User agent
        echo $_SERVER['HTTP_USER_AGENT'] . "\r\n";

        // If you needed all headers:
        foreach(getallheaders() as $header => $value)
          echo "$header: $value\r\n";

        // If you wanted raw request data vs. parsed POST data:
        $postdata = file_get_contents('php://input');
        if(strlen($postdata)) echo $postdata."\r\n";

        // Post data / Cookies / Files
        if(count($_POST) || count($_COOKIE)) {
            ob_start();

            echo "POST\n";
            var_dump($_POST);

            echo "COOKIES\n";
            var_dump($_COOKIE);

            echo "FILES\n";
            var_dump($_FILES);

            $postdata = ob_get_clean();
            echo str_replace("\n","\r\n",$postdata);
        }
        echo "\r\n";

        // usage of random character string discourages guessing
        // the url if the directory is web-accessible; but, if at
        // all possible, make it inaccessible:
        file_put_contents('/var/log/requests.log',ob_get_clean(),FILE_APPEND);
    }

    // then, a simple maintenance page:
?>
<!DOCTYPE html>
<html>
    <head>
        <title>Some Title</title>
    </head>
    <body>
        <p class="notice">
            Add some styling here
        </p>
    </body>
</html>
