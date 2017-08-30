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


class RuleWithUserID extends Rule
{
    const __UserIDType_Any = 0;
    const __UserIDType_Unknown = 1;
    const __UserIDType_Known = 2;
    const __UserIDType_PreLogon = 3;
    const __UserIDType_Custom = 4;

    static private $__UserIDTypes = Array(
        self::__UserIDType_Any => 'any',
        self::__UserIDType_Unknown => 'unknown',
        self::__UserIDType_Known => 'known',
        self::__UserIDType_PreLogon => 'pre-logon',
        self::__UserIDType_Custom => 'custom'
    );

    protected $_userIDType = self::__UserIDType_Any;

    /** @var string[] */
    protected $_users = Array();

    function userID_IsAny()
    {
        return ($this->_userIDType == self::__UserIDType_Any);
    }
    function userID_IsUnknown()
    {
        return $this->_userIDType == self::__UserIDType_Unknown;
    }
    function userID_IsKnown()
    {
        return $this->_userIDType == self::__UserIDType_Known;
    }
    function userID_IsPreLogon()
    {
        return $this->_userIDType == self::__UserIDType_PreLogon;
    }
    function userID_IsCustom()
    {
        return $this->_userIDType == self::__UserIDType_Custom;
    }

    /**
     * @return string
     */
    function userID_type()
    {
        return self::$__UserIDTypes[$this->_userIDType];
    }

    function userID_getUsers()
    {
        return $this->_users;
    }

    /**
     * For developers only
     */
    function userID_loadUsersFromXml()
    {
        $xml = DH::findFirstElement('source-user', $this->xmlroot);
        if( $xml === false )
            return;

        foreach($xml->childNodes as $node)
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $content = $node->textContent;
            if( strlen($content) == 0 )
                derr('empty username in rule', $node);

            if( $content == 'any' )
                return;
            if( $content == 'unknown' )
            {
                $this->_userIDType = self::__UserIDType_Unknown;
                return;
            }
            if( $content == 'known' )
            {
                $this->_userIDType = self::__UserIDType_Known;
                return;
            }
            if( $content == 'pre-logon' )
            {
                $this->_userIDType = self::__UserIDType_PreLogon;
                return;
            }

            $this->_users[] = $content;
        }

        $this->_userIDType = self::__UserIDType_Custom;
    }

}
