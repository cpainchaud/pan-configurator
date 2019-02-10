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

class Template
{
    use ReferencableObject;
    use PathableName;
    use PanSubHelperTrait;

    /** @var PanoramaConf */
    public $owner;

    /** @var  PANConf */
    public $deviceConfiguration;

    protected $FirewallsSerials = Array();

    /**
     * Template constructor.
     * @param string $name
     * @param PanoramaConf $owner
     */
    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->deviceConfiguration = new PANConf(null, null, $this);
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("template name not found\n", $xml);

        $tmp = DH::findFirstElementOrDie('config', $xml);

        $this->deviceConfiguration->load_from_domxml($tmp);

        $this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml( $xml );
        foreach( $this->FirewallsSerials as $serial)
        {
            $managedFirewall = $this->owner->managedFirewallsStore->find( $serial );
            if( $managedFirewall !== null )
                $managedFirewall->addTemplate( $this->name );
        }
    }

    public function name()
    {
        return $this->name;
    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$this->name."']";

        return $str;
    }

    public function isTemplate()
    {
        return true;
    }

}

