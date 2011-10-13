#!/usr/bin/php -n
<?

dl("zmq.so");

define('RLM_MODULE_REJECT',0);		/* immediately reject the request */
define('RLM_MODULE_FAIL',1);		/* module failed, don't reply */
define('RLM_MODULE_OK',2);			/* the module is OK, continue */
define('RLM_MODULE_HANDLED',3);		/* the module handled the request, so stop. */
define('RLM_MODULE_INVALID',4); 	/* the module considers the request invalid. */
define('RLM_MODULE_USERLOCK',5);	/* reject the request (user is locked out) */
define('RLM_MODULE_NOTFOUND',6);	/* user not found */
define('RLM_MODULE_NOOP','7');		/* module succeeded without doing anything */
define('RLM_MODULE_UPDATED',8);		/* OK (pairs modified) */
define('RLM_MODULE_NUMCODES',9);	/* How many return codes there are */


//connect to the queue as a worker
$context = new ZMQContext();
$server =$context->getSocket(ZMQ::SOCKET_REP);
$server->connect("tcp://localhost:5455");
echo "worker started\n";
while(true) {
    $message = $server->recv();
	echo "received job" . date("r") . "\n";
	$data=json_decode($message,true);
	print_r($data);

	if (1) {
		echo "allowing user {$data['request']['User-Name']}\n";
		if (!empty($data['request']['User-Password'])) {
			$data['control']['Cleartext-Password']=$data['request']['User-Password'];
		}
		$data['statuscode']=RLM_MODULE_OK;
	} else {
		$data['statuscode']=RLM_MODULE_REJECT;
	}
    echo "Sending response\n";
	//print_r($data);
	$response=json_encode($data)."\0";
    $server->send($response);
}
