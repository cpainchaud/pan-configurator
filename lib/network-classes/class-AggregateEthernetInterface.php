<?php
/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

class AggregateEthernetInterface extends EthernetInterface
{

    /** @var string */
    public $type = 'aggregate';

    public function isEthernetType() { return false; }

    public function isAggregateType() { return true; }


    static public $templatexml = '<entry name="**temporarynamechangeme**">
  <layer3>
    <ipv6>
      <neighbor-discovery>
        <router-advertisement>
          <enable>no</enable>
        </router-advertisement>
      </neighbor-discovery>
    </ipv6>
    <ndp-proxy>
      <enabled>no</enabled>
    </ndp-proxy>
    <lldp>
      <enable>no</enable>
    </lldp>
    <ip></ip>
  </layer3>
</entry>';

}