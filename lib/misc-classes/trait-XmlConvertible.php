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


trait XmlConvertible
{
    /** @var DOMElement|null $xmlroot  */
    public $xmlroot = null;

	function &getXmlText_inline()
	{
		return DH::dom_to_xml($this->xmlroot, -1, false);
	}

    /**
     * @param bool|true $indenting
     * @return string
     */
	function &getXmlText( $indenting = true)
	{

		if( $indenting )
			return DH::dom_to_xml($this->xmlroot, 0, true);
		return DH::dom_to_xml($this->xmlroot, -1, true);
	}

    /**
     * @return string
     */
    function &getChildXmlText_inline()
    {
        return DH::domlist_to_xml($this->xmlroot->childNodes, -1, false);
    }

    public function API_sync()
    {
        $xpath = DH::elementToPanXPath($this->xmlroot);
        $con = findConnectorOrDie($this);

        $con->sendEditRequest($xpath, $this->getXmlText_inline());
    }

}

