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

class VlanInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    protected $_ipv4Addresses = Array();

    /** @var string */
    public $type = 'vlan';

    function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }


    public function isVlanType()
    {
        return true;
    }

    public function load_from_domxml( DOMElement $xml )
    {
        /*
              <entry name="vlan.1">
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

                <adjust-tcp-mss>
                  <enable>no</enable>
                </adjust-tcp-mss>
              </entry>
         */
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("vlan name name not found\n");

        $ipNode = DH::findFirstElement('ip', $xml);
        if( $ipNode !== false )
        {
            foreach( $ipNode->childNodes as $l3ipNode )
            {
                if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                $this->_ipv4Addresses[] = $l3ipNode->getAttribute('name');
            }
        }


    }

    public function getIPv4Addresses()
    {
        return $this->_ipv4Addresses;
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @return bool
     * @param string $name new name for the rule
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return true;

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return true;

    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getVlanIfStoreXPath()."/entry[@name='".$this->name."']";

        return $str;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
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
<adjust-tcp-mss>
  <enable>no</enable>
</adjust-tcp-mss>
</entry>';
}