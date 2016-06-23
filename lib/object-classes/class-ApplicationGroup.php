<?php
/*
 * Copyright (c) 2014-2016 Christophe Painchaud <shellescape _AT_ gmail.com>
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


class ApplicationGroup
{
    use ReferencableObject;
    use PathableName;
    use XmlConvertible;
    use ApplicationCommon;

    /** @var AppStore */
    public $owner = null;

    /** @var Application[]|ApplicationGroup  */
    protected $_members = Array();

    public function __construct($name,$owner=null)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * returns number of members in this group
     * @return int
     */
    public function count()
    {
        return count($this->_members);
    }

    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE || strlen($this->name) < 1 )
            derr("name not found or invalid\n", $xml);

        foreach( $xml->childNodes as $node)
        {
            if( $node->nodeType != 1 ) continue;
            /** @var DOMElement $node */

            $memberName = $node->textContent;

            if( strlen($memberName) < 1 )
                derr('found a member with empty name !', $node);

            $f = $this->owner->findOrCreateTmp($memberName, $this, true);

            if( isset($this->_members[$memberName]) )
                    mwarning("service '{$memberName}' is already part of group '{$this->name}', you should review your your config file");
            else
                $this->_members[$memberName] = $f;

        }
    }
}