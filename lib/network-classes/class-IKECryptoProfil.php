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

/**
 * Class IkeCryptoProfil
 * @property IkeCryptoProfileStore $owner
 */
class IkeCryptoProfil
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    //TODO: 20180403 these three variables are multi member, extend to array
    public $hash = 'notfound';
    public $dhgroup = 'notfound';
    public $encryption = 'notfound';

    public $lifetime_seconds = '';
    public $lifetime_minutes = '';
    public $lifetime_hours = '';
    public $lifetime_days = '';

    public $ikecryptoprofiles = Array();



    const group1 = 'group1';
    const group2 = 'group2';
    const group5 = 'group5';
    const group14 = 'group14';
    const group19 = 'group19';
    const group20 = 'group20';

    static public $dhgroups = Array(
        self::group1 => 'group1',
        self::group2 => 'group2',
        self::group5 => 'group5',
        self::group14 => 'group14',
        self::group19 => 'group19',
        self::group20 => 'group20'
    );


    const md5 = 'md5';
    const sha1 = 'sha1';
    const sha256 = 'sha256';
    const sha384 = 'sha384';
    const sha512 = 'sha512';

    static public $hashs = Array(
        self::md5 => 'md5',
        self::sha1 => 'sha1',
        self::sha256 => 'sha256',
        self::sha384 => 'sha384',
        self::sha512 => 'sha512'
    );


    const des = 'des';
    const tripledes = '3des';
    const aes128cbc = 'aes-128-cbc';
    const aes192cbc = 'aes-192-cbc';
    const aes256cbc = 'aes-256-cbc';

    static public $encryptions = Array(
        self::des => 'des',
        self::tripledes => '3des',
        self::aes128cbc => 'aes-128-cbc',
        self::aes192cbc => 'aes-192-cbc',
        self::aes256cbc => 'aes-256-cbc'
    );

    /**
     * IkeCryptoProfile constructor.
     * @param string $name
     * @param IkeCryptoProfileStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml( $xml )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name not found\n");


        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'hash' )
                $this->hash = DH::findFirstElementOrCreate('member', $node)->textContent;

            if( $node->nodeName == 'dh-group' )
                $this->dhgroup = DH::findFirstElementOrCreate('member', $node)->textContent;

            if( $node->nodeName == 'encryption' )
                $this->encryption = DH::findFirstElementOrCreate('member', $node)->textContent;

            if( $node->nodeName == 'lifetime' )
            {
                if( DH::findFirstElement('seconds', $node) != null )
                    $this->lifetime_seconds = DH::findFirstElement('seconds', $node)->textContent;
                elseif( DH::findFirstElement('minutes', $node) != null )
                    $this->lifetime_minutes = DH::findFirstElement('minutes', $node)->textContent;
                elseif( DH::findFirstElement('hours', $node) != null )
                    $this->lifetime_hours = DH::findFirstElement('hours', $node)->textContent;
                elseif( DH::findFirstElement('days', $node) != null )
                    $this->lifetime_days = DH::findFirstElement('days', $node)->textContent;
            }
        }
    }

    /**
     * return true if change was successful false if not (duplicate IkeCryptoProfil name?)
     * @return bool
     * @param string $name new name for the IkeCryptoProfil
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return true;

        if( preg_match( '/[^0-9a-zA-Z_\-\s]/' , $name ) )
        {
            $name = preg_replace('/[^0-9a-zA-Z_\-\s]/',"", $name);
            print "new name: ".$name." \n";
            #mwarning( 'Name will be replaced with: '.$name."\n" );
        }

        /* TODO: 20180331 finalize needed
        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this,$oldname);
            }
            else
                return false;
        }
*/
        $this->name = $name;
        $this->xmlroot->setAttribute('name', $name);

        return true;
    }


    public function setDHgroup($dhgroup )
    {
        if( $this->dhgroup == $dhgroup )
            return true;

        if( !isset( self::$dhgroups[ $dhgroup ] ) )
        {
            $dhgroup = preg_replace('/\D/', '', $dhgroup);
            $dhgroup = "group".$dhgroup;
            print " *** new dhgroup name: ".$dhgroup."\n";
        }

        $this->dhgroup = $dhgroup;

        $tmp_gateway = DH::findFirstElementOrCreate('dh-group', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('member', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $dhgroup);

        return true;
    }

    public function sethash($hash )
    {
        if( $this->hash == $hash )
            return true;

        if( !isset( self::$hashs[ $hash ] ) )
        {
            $hash = str_replace( "-", "", $hash);
            print " *** hash: ".$hash." wrong\n";
            #mwarning( 'authentication wrong' );
        }
        
        $this->hash = $hash;

        $tmp_gateway = DH::findFirstElementOrCreate('hash', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('member', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $hash);

        return true;
    }

    public function setencryption( $encryption )
    {
        if( $this->encryption == $encryption )
            return true;

        if( !isset( self::$encryptions[ $encryption ] ) )
        {
            $encryption = str_replace( "-", "", $encryption);
            print " *** encryption: ".$encryption." wrong\n";
            #mwarning( 'authentication wrong' );
        }
        
        $this->encryption = $encryption;

        $tmp_gateway = DH::findFirstElementOrCreate('encryption', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('member', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $encryption);

        return true;
    }

    public function setlifetime( $timertype, $time )
    {
        #if( $this->encryption == $encryption )
            #return true;

        if( intval( $time ) > 65535 )
            mwarning( 'time value of: '.$time." is greater then 65535\n" );

        if( $timertype == 'seconds' )
            $this->lifetime_seconds = $time;
        elseif( $timertype == 'minutes' )
            $this->lifetime_minutes = $time;
        elseif( $timertype == 'hours' )
            $this->lifetime_hours = $time;
        elseif( $timertype == 'days' )
            $this->lifetime_days = $time;

        $tmp_gateway = DH::findFirstElementOrCreate('lifetime', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate($timertype, $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $time);

        return true;
    }

    public function isIkeCryptoProfilType()
    {
        return true;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
<hash>
</hash>
<dh-group>
</dh-group>
<encryption>
</encryption>
<lifetime>
</lifetime>
</entry>';


}