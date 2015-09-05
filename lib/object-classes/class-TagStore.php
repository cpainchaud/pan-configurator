<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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
 * Class TagStore
 * @property Tag[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf $owner
 */
class TagStore extends ObjStore
{
	protected $parentCentralStore = null;
	
	public static $childn = 'Tag';
	
	public function __construct($owner)
	{
		$this->classn = &self::$childn;
		
		$this->owner = $owner;
		$this->o = Array();

        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->tagStore;
		else
            $this->findParentCentralStore();
		
	}

    /**
     * @param $name
     * @param null $ref
     * @param bool $nested
     * @return null|Tag
     */
	public function find($name, $ref=null, $nested = true)
	{
		$f = $this->findByName($name,$ref);

        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore !== null )
            return $this->parentCentralStore->find( $name, $ref, $nested);

        return null;
	}

	public function removeAllTags()
	{
		$this->removeAll();
		$this->rewriteXML();
	}

    /**
     * add a Zone to this store. Use at your own risk.
     * @param Tag
     * @param bool
     * @return bool
     */
    public function addTag( Tag $Obj, $rewriteXML = true )
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            if( $this->xmlroot !== null )
            {
                $this->xmlroot->appendChild($Obj->xmlroot);
            }
        }
        return $ret;
    }

	/**
	*
	*/
	public function findAvailableTagName($base, $suffix, $startCount = '')
	{
		$maxl = 31;
		$basel = strlen($base);
		$suffixl = strlen($suffix);
		$inc = $startCount;
		$basePlusSuffixL = $basel + $suffixl;

		while(true)
		{

			$incl = strlen(strval($inc));

			if( $basePlusSuffixL + $incl > $maxl )
			{
				$newname = substr($base,0, $basel-$suffixl-$incl).$suffix.$inc;
			}
			else
				$newname = $base.$suffix.$inc;

			if( is_null($this->find($newname)) )
				return $newname;

            if( $startCount == '' )
                $startCount = 0;
			$inc++;
		}
	}
	
	
	
	/**
	* returns a copy of current Tag array
	*
	*/
	public function tags()
	{
		return $this->o;
	}



    function createTag($name, $ref=null)
    {
        if( $this->find($name, null, false ) !== null )
            derr('Tag named "'.$name.'" already exists, cannot create');

        if( $this->xmlroot === null )
            return $this->createTmp($name, $ref);

        $newTag = new Tag($name, $this, true);

        if( $ref !== null )
            $newTag->addReference($ref);

        $this->addTag($newTag);

        return $newTag;
    }

    function findOrCreate($name, $ref=null, $nested=true)
    {
        $f = $this->find($name, $ref, $nested);

        if( $f !== null )
            return $f;

        return $this->createTag($name, $ref);
    }

    function API_createTag($name, $ref=null)
    {
        $newTag = $this->createTag($name, $ref);

        if( !$newTag->isTmp() )
        {
            $xpath = $this->getXPath();
            $con = findConnectorOrDie($this);
            $element = $newTag->getXmlText_inline();
            $con->sendSetRequest($xpath, $element);
        }

        return $newTag;
    }

    public function &getXPath()
    {
        $str = '';

        $ownerClass = get_class($this->owner);

        if( $ownerClass == 'VirtualSystem' || $ownerClass == 'DeviceGroup' )
            $str = $this->owner->getXPath();
        elseif( $ownerClass == 'PanoramaConf' )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str.'/tag';

        return $str;
    }


	
	public function rewriteXML()
	{
        if( $this->xmlroot === null )
            return;

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o)
        {
            if( !$o->isTmp() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
	}
	
	
	/**
	*
	* @ignore
	*/
	protected function findParentCentralStore()
	{
		$this->parentCentralStore = null;
		
			$cur = $this->owner;
			while( isset($cur->owner) && !is_null($cur->owner) )
			{
				$ref = $cur->owner;
				if( isset($ref->tagStore) &&
					!is_null($ref->tagStore)				)
				{
					$this->parentCentralStore = $ref->tagStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$cur = $ref;
			}

	}
	
}


trait centralTagStore
{
	/**
	* @var TagStore central tag store
	*/
	public $tagStore=null;
	
	/**
	* @return TagStore
	*/
	public function tagStore()
	{
		return $this->tagStore;
	}
}

