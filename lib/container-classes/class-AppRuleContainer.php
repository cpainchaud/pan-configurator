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
 * Class AppRuleContainer
 * @property App[] $o
 *
 */
class AppRuleContainer extends ObjRuleContainer
{
    public static $childn = 'App';

    /** @var null|AppStore */
    public $parentCentralStore = null;



    public function __construct($owner)
    {
        $this->owner = $owner;

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
        if( ! $this->addApp($Obj, $rewritexml) )
            return false;

        $this->API_sync();

        return true;
    }


    /**
     * remove an App to this store. Be careful if you remove last zone as
     * it would become 'any' and won't let you do so.
     * @param App $Object
     * @param bool $rewritexml
     * @param bool $forceAny
     * @return bool
     */
    public function removeApp( App $Object, $rewritexml = true, $forceAny = false )
    {
        $count = count($this->o);

        $ret = $this->remove($Object);

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
     * remove an App to this store. Be careful if you remove last zone as
     * it would become 'any' and won't let you do so.
     * @param App $Object
     * @param bool $rewritexml
     * @param bool $forceAny
     * @return bool
     */
    public function API_removeApp( App $Object, $rewritexml = true, $forceAny = false )
    {
        if( ! $this->removeApp($Object, $rewritexml, $forceAny) )
            return false;

        $this->API_sync();

        return true;
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
    public function load_from_domxml($xml)
    {
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = $xml;
        $i=0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( $i == 0 && $node->textContent == 'any' )
            {
                return;
            }

            if( strlen($node->textContent) < 1 )
            {
                derr('this container has members with empty name!', $node);
            }

            $f = $this->parentCentralStore->findOrCreate( $node->textContent, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML()
    {
        DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', true);
    }

    public function toString_inline()
    {
        if( count($this->o) == 0 )
        {
            $out = '**ANY**';
            return $out;
        }

        $out = parent::toString_inline();
        return $out;
    }


    public function merge($other)
    {
        $this->fasthashcomp = null;

        if( count($this->o) == 0 )
            return;

        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach($other->o as $s)
        {
            $this->addApp($s);
        }
    }


    public function setAny()
    {
        $this->removeAll();

        $this->rewriteXML();
    }

    public function API_setAny()
    {
        $this->setAny();
        $this->API_sync();
    }

    public function members()
    {
        return $this->o;
    }

    public function membersExpanded($keepGroupsInList=false)
    {
        $localA = Array();

        if( count($this->o) == 0 )
            return $localA;

        foreach( $this->o as $member )
        {
            if( $member->isContainer() )
            {
                foreach( $member->containerApps() as $containerApp )
                {
                    if( $containerApp->isContainer() )
                    {
                        foreach( $containerApp->containerApps() as $containerApp1 )
                            $localA[] = $containerApp1;
                    }
                    else
                        $localA[] = $containerApp;
                }
            }
            else
                $localA[] = $member;
        }

        $localA = array_unique_no_cast($localA);

        return $localA;
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
            while( isset($curo->owner) && $curo->owner !== null )
            {

                if( isset($curo->owner->appStore) &&
                    $curo->owner->appStore !== null			)
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

    /**
     * @param App|string can be Tag object or tag name (string). this is case sensitive
     * @param bool
     * @return bool
     */
    public function hasApp( $tag, $caseSensitive = true )
    {
        return $this->has($tag, $caseSensitive);
    }

    /**
     * @param App|string can be Tag object or tag name (string). this is case sensitive
     * @param bool
     * @return bool
     */
    public function includesApp($tag, $caseSensitive = true )
    {
        if( is_string($tag) )
        {
            if( !$caseSensitive )
                $tag = strtolower($tag);
            $app = $this->parentCentralStore->find($tag);
            if( $app == null )
                derr( "\n\n**ERROR** cannot find object with name '{$tag}' in location '{$this->getLocationString()}' or its parents. If you didn't write a typo then try a REGEX based filter instead\n\n" );
        }
        else
            $app = $tag;

        if( !$app->isContainer() )
        {
            foreach( $this->apps() as $singleapp)
            {
                if( $singleapp->isContainer() )
                {
                    foreach( $singleapp->containerApps() as $containerApp )
                    {
                        if( $containerApp == $app )
                            return TRUE;
                    }
                }
            }
        }
        if( $this->has($app, $caseSensitive) )
            return true;

        return false;
    }

    /**
     * @param App|string can be Tag object or tag name (string). this is case sensitive
     * @param bool
     * @return bool
     */
    public function includedInApp($tag, $caseSensitive = true )
    {
        if( is_string($tag) )
        {
            if( !$caseSensitive )
                $tag = strtolower($tag);
            $app = $this->parentCentralStore->find($tag);
            if( $app == null )
                derr( "\n\n**ERROR** cannot find object with name '{$tag}' in location '{$this->getLocationString()}' or its parents. If you didn't write a typo then try a REGEX based filter instead\n\n" );
        }
        else
            $app = $tag;


        if( $app->isContainer() )
        {
            foreach( $app->containerApps() as $containerApp )
            {
                if( $this->has($containerApp, $caseSensitive) )
                    return TRUE;
            }
        }

        if( $this->has($app, $caseSensitive) )
            return true;

        return false;
    }

    public function customApphasSignature()
    {
        foreach( $this->apps() as $singleapp)
        {
            if( $singleapp->CustomHasSignature() )
                return true;
        }

        return false;
    }
}





