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
 * Class AppRuleContainer
 * @property App[] $o
 *
 */
class AppRuleContainer extends ObjRuleContainer
{
    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot=null;

    public static $childn = 'App';

    /**
     * @var null|AppStore
     */
    public $parentCentralStore = null;



    public function AppRuleContainer($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = Array();

        $this->findParentCentralStore();
    }

    public function find($name, $ref=null)
    {
        return $this->findByName($name,$ref);
    }


    /**
     * add a App to this store
     *
     */
    public function addApp( App $Obj, $rewritexml = true )
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
     * add a App to this store
     *
     */
    public function API_addApp( App $Obj, $rewritexml = true )
    {
        $ret = addApp($Obj, $rewritexml);

        if( !$ret )
            return false;

        $con = findConnectorOrDie($this);
        $xpath = &$this->owner->getXPath();

        if( $this->count() == 1)
        {
            $con->sendDeleteRequest($xpath.'/application');
        }

        $con->sendSetRequest($xpath.'/application', '<member>'.$Obj->name().'</member>');

        return true;
    }

    public function API_synchronize()
    {

        $con = findConnectorOrDie($this);

        $xpath = &$this->owner->getXPath();
        $con->sendDeleteRequest($xpath.'/application');

        $element = &array_to_xml( $this->xmlroot, -1, false);
        $con->sendSetRequest($xpath, $element);
    }



    /**
     * remove an App to this store. Be careful if you remove last zone as
     * it would become 'any' and won't let you do so.
     * @param bool $rewritexml
     * @param bool $forceAny
     */
    public function removeApp( App $Obj, $rewritexml = true, $forceAny = false )
    {
        $count = count($this->o);

        $ret = $this->remove($Obj);

        if( $ret && $count == 1 && !$forceAny )
        {
            derr("you are trying to remove last App from a rule which will set it to ANY, please use forceAny=true for object: "
                .$this->toString() ) ;
        }

        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * returns true if rule app is Any
     *
     */
    public function isAny()
    {
        return  ( count($this->o) == 0 );
    }


    /**
     * return an array with all Apps in this store
     *
     */
    public function apps()
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

        foreach( $xml['children'] as &$cur )
        {

            if( strtolower($cur['content']) == 'any' )
            {
                return;
            }

            $f = $this->parentCentralStore->findOrCreate( $cur['content'], $this);
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
        {
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', true);
        }
        else
        {
            Hosts_to_xmlA($this->xmlroot['children'], $this->o, 'member', true);
        }
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

                if( isset($curo->owner->appStore) &&
                    !is_null($curo->owner->appStore)				)
                {
                    $this->parentCentralStore = $curo->owner->appStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $curo = $curo->owner;
            }
        }

        //print $this->toString().": no parent store found\n";

    }


}





