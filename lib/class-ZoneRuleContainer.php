<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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
 * Class ZoneRuleContainer
 *
 */
class ZoneRuleContainer extends ObjRuleContainer
{
    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot=null;

    public static $childn = 'Zone';

    /**
     * @var null|ZoneStore
     */
    public $parentCentralStore = null;



    public function ZoneRuleContainer($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = Array();

        $this->findParentCentralStore();
    }


    /**
     * add a Zone to this store
     * @param bool $rewritexml
     * @return bool
     */
    public function addZone( Zone $Obj, $rewritexml = true )
    {
        $fasthashcomp=null;

        $ret = $this->add($Obj);
        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * add a Zone to this store
     * @param bool $rewritexml
     * @return bool
     */
    public function API_addZone( Zone $Obj, $rewritexml = true )
    {
        if( $this->addZone($Obj, $rewritexml) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 1 )
            {
                $url = "type=config&action=delete&xpath=" . $xpath;
                $con->sendRequest($url);
            }

            $url = "type=config&action=set&xpath=$xpath&element=<member>".$Obj->name()."</member>";
            $con->sendRequest($url);

            return true;
        }

        return false;
    }


    /**
     * remove a Zone a Zone to this store. Be careful if you remove last zone as
     * it would become 'any' and won't let you do so.
     * @param bool $rewritexml
     * @param bool $forceAny
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeZone( Zone $Obj, $rewritexml = true, $forceAny = false )
    {
        $count = count($this->o);

        $ret = $this->remove($Obj);

        if( $ret && $count == 1 && !$forceAny  )
        {
            derr("you are trying to remove last Zone from a rule which will set it to ANY, please use forceAny=true for object: "
                .$this->toString() ) ;
        }

        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }


    public function API_removeZone( Zone $Obj, $rewritexml = true, $forceAny = false )
    {
        if( $this->removeZone($Obj, $rewritexml, $forceAny) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 0 )
            {
                $url = "type=config&action=delete&xpath=" . $xpath;
                $con->sendRequest($url);
                $url = "type=config&action=set&xpath=$xpath&element=<member>any</member>";
                $con->sendRequest($url);
                return true;
            }

            $url = "type=config&action=delete&xpath=" . $xpath."/member[text()='".$Obj->name()."']";
            $con->sendRequest($url);

            return true;
        }

        return false;
    }

    public function setAny()
    {
        foreach( $this->o as $o )
        {
            $this->removeZone($o, false, true);
        }

        $this->rewriteXML();
    }

    /**
     * @param Zone|string $zone can be Zone object or zone name (string). this is case sensitive
     * @return bool
     */
    public function hasZone( $zone, $caseSensitive = true )
    {
        return $this->has($zone, $caseSensitive);
    }



    /**
     * return an array with all Zones in this store
     * @return array
     */
    public function zones()
    {
        return $this->o;
    }


    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_xml(&$xml)
    {
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = &$xml;
        $cur = &$xml['children'];

        $c = count($cur);
        $k = array_keys($cur);

        for( $i=0; $i<$c; $i++ )
        {

            if( $c == 1 && strtolower($cur[$k[$i]]['content']) == 'any' )
            {
                return;
            }

            $f = $this->parentCentralStore->findOrCreate( $cur[$k[$i]]['content'], $this);
            $this->o[] = $f;
        }

    }

    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = $xml;
        $i=0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( $i == 0 && strtolower($node->textContent) == 'any' )
            {
                return;
            }

            $f = $this->parentCentralStore->findOrCreate( $node->textContent, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML()
    {
        if( PH::$UseDomXML === TRUE )
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', true);
        else
            Hosts_to_xmlA($this->xmlroot['children'], $this->o, 'member', true);

    }

    public function &toString_inline()
    {
        if( count($this->o) == 0 )
        {
            $out = '**ANY**';
            return $out;
        }

        $out = parent::toString_inline();
        return $out;
    }



    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $curo = $this;
            while( isset($curo->owner) && !is_null($curo->owner) )
            {

                if( isset($curo->owner->zoneStore) &&
                    !is_null($curo->owner->zoneStore)				)
                {
                    $this->parentCentralStore = $curo->owner->zoneStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $curo = $curo->owner;
            }
        }

        //print $this->toString().": no parent store found\n";

    }


    /**
     * Merge this set of Zones with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     *
     */
    public function merge($other)
    {
        $this->fasthashcomp = null;


        // we should check if we are negated?

        if( count($this->o) == 0 )
            return;

        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach($other->o as $s)
        {
            $this->addZone($s);
        }

    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param $other
     * @param $anyIsAcceptable
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(ZoneRuleContainer $other, $anyIsAcceptable=true )
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return false;
        }

        if( $this->count() == 0 )
            return true;

        if( $other->count() == 0 )
            return false;

        $zones = $other->zones();

        foreach( $zones as $zone )
        {
            if( !$this->inStore($zone) )
                return false;
        }

        return true;

    }

    public function API_setAny()
    {
        $this->setAny();
        $xpath = &$this->getXPath();
        $con = findConnectorOrDie($this);

        $url = "type=config&action=delete&xpath=".$xpath;
        $con->sendRequest($url);

        $url = "type=config&action=set&xpath=$xpath&element=<member>any</member>";
        $con->sendRequest($url);
    }


    public function &getXPath()
    {

        $str = $this->owner->getXPath().'/'.$this->name;

        return $str;

    }

    /**
     * @return bool
     */
    public function isAny()
    {
        return ( count($this->o) == 0);
    }
}





