<?php
// Scans one file with the quelda CLI. Only exit code 0 means valid.
function quelda_scan(string $path, ?string $policy = null, int $timeout = 30): array
{
    $args = ['quelda', 'scan', $path];
    if ($policy !== null) {
        array_push($args, '--policy', $policy);
    }
    // An array command runs without a shell (PHP >= 7.4).
    $proc = proc_open($args, [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if ($proc === false) {
        return ['valid' => false, 'status' => 'NOT STARTED'];
    }
    stream_set_blocking($pipes[1], false);
    $out = '';
    $deadline = microtime(true) + $timeout;
    do {
        $out .= stream_get_contents($pipes[1]);
        $status = proc_get_status($proc);
        if ($status['running'] && microtime(true) > $deadline) {
            proc_terminate($proc, 9);
            proc_close($proc);
            return ['valid' => false, 'status' => 'TIMEOUT'];
        }
        usleep(10000);
    } while ($status['running']);
    $out .= stream_get_contents($pipes[1]);
    proc_close($proc);
    $verdict = json_decode($out, true) ?? ['status' => 'EXIT ' . $status['exitcode']];
    $verdict['valid'] = $status['exitcode'] === 0;
    return $verdict;
}

if (realpath($argv[0] ?? '') === __FILE__) {
    $v = quelda_scan($argv[1]);
    echo 'valid=' . ($v['valid'] ? 'true' : 'false') . ' status=' . $v['status'] . "\n";
}
