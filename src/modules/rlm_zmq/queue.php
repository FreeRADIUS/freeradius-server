#!/usr/bin/php -n
<?

dl("zmq.so");

$context = new ZMQContext();
$clients= new ZMQSocket($context, ZMQ::SOCKET_XREP);
$workers= new ZMQSocket($context, ZMQ::SOCKET_XREQ);

$clients->bind('tcp://*:5454');
$workers->bind('tcp://*:5455');

$poll = new ZMQPoll();
$poll->add($clients, ZMQ::POLL_IN);
$poll->add($workers, ZMQ::POLL_IN);
$readable = $writeable = array();

echo "zeromq queue is ready...\n";
while(true) {
    $events = $poll->poll($readable, $writeable);
    foreach($readable as $socket) {
        if($socket === $clients) {
			echo "received client message(s), sending to worker(s)\n";
            $messages = $clients->recvMulti();
            $workers->sendMulti($messages);
        } else if($socket === $workers) {
			echo "received worker response(s) sending to client(s)\n";
            $messages = $workers->recvMulti();
            $clients->sendMulti($messages);
        }
    }
}
