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
 * Class TagStore
 * @property Tag[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf $owner
 * @method Tag[] getAll()
 */
class TagStore extends ObjStore
{
    /** @var null|TagStore */
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
     * add a Tag to this store. Use at your own risk.
     * @param Tag $Obj
     * @param bool
     * @return bool
     */
    public function addTag( Tag $Obj, $rewriteXML = true )
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            if( $this->xmlroot === null )
                $this->xmlroot = DH::findFirstElementOrCreate('tag', $this->owner->xmlroot);

            $this->xmlroot->appendChild($Obj->xmlroot);
        }
        return $ret;
    }

	/**
	* @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
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

			if( $this->find($newname) === null )
				return $newname;

            if( $startCount == '' )
                $startCount = 0;
			$inc++;
		}
	}
	
	
	
	/**
	* return tags in this store
	* @return Tag[]
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
        {
            if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() )
                $this->xmlroot = DH::findFirstElementOrCreate('tag', $this->owner->xmlroot);
            else
                $this->xmlroot = DH::findFirstElementOrCreate('tag', $this->owner->sharedroot);
        }

        $newTag = new Tag($name, $this);
        $newTag->owner = null;

        $newTagRoot = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, Tag::$templatexml);
        $newTagRoot->setAttribute('name', $name);
        $newTag->load_from_domxml($newTagRoot);

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


    /**
     * @param Tag $tag
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeTag( Tag $tag )
    {
        $ret = $this->remove($tag);

        if( $ret && !$tag->isTmp() && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($tag->xmlroot);
        }

        return $ret;
    }

    /**
     * @param Tag $tag
     * @return bool
     */
    public function API_removeTag(Tag $tag)
    {
        $xpath = null;

        if( !$tag->isTmp() )
            $xpath = $tag->getXPath();

        $ret = $this->removeTag($tag);

        if( $ret && !$tag->isTmp())
        {
            $con = findConnectorOrDie($this);
            $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str.'/tag';

        return $str;
    }


    private function &getBaseXPath()
    {
        if ($this->owner->isPanorama() ||  $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            $str = $this->owner->getXPath();


        return $str;
    }

    public function &getTagStoreXPath()
    {
        $path = $this->getBaseXPath().'/tag';
        return $path;
    }
	
	public function rewriteXML()
	{
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
                DH::findFirstElementOrCreate('tag', $this->owner->xmlroot);
        }

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
			while( isset($cur->owner) && $cur->owner !== null )
			{
				$ref = $cur->owner;
				if( isset($ref->tagStore) &&
					$ref->tagStore !== null			)
				{
					$this->parentCentralStore = $ref->tagStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$cur = $ref;
			}

	}
	
}


