# NNN - <slug>

state:     lead | confirmed | triaged | reported | killed
class:     <xss|sqli|idor|authz|ssrf|...>
host:      <host>
endpoint:  <METHOD /path>
severity:  <Critical|High|Medium|Low>   CVSS: <vector>
found:     <YYYY-MM-DD HH:MM UTC>

## What
<one paragraph: what is wrong>

## Evidence
<the minimal request/response pair, redacted>

## Reproduction
<paste-into-shell commands, with the two accounts named>

## Triage (zp-triage - all seven, in writing)
verdict:              PASS | KILL | DOWNGRADE | CHAIN-REQUIRED
1 exploitable now?    <yes/no - why>
2 no unusual action?  <yes/no>
3 harm:               <named harm>
4 reproduced:         <how many times, which stacks>
5 in scope:           <asset, class, method - re-checked against scope.yaml>
6 dedup:              <sources searched, result>
7 provable severity:  <what the evidence actually supports>
browser verified:     yes | no | N/A
devil's advocate:     SURVIVES | DOWNGRADE | KILLED - <strongest counter-argument, and the answer>

## Chain
capability gained:  read | write | execute | control
next links tried:   <at least 3, or 20 minutes>
result:             <terminal impact reached, or chain dead end + evidence>

## Cleanup
<what you created and removed>
