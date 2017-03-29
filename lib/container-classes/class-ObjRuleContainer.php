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
 * Class ObjRuleContainer
 * @property $fasthashcomp string
 */
class ObjRuleContainer
{
    use PathableName;
    use XmlConvertible;


    public $owner = null;
    public $name = '';

    public $o = Array();

    public function count()
    {
        return count($this->o);
    }

    public function setName($newname)
    {
        $this->name = $newname;
    }


    /**
     * Return true if all objects from this store are the same then in the other store.
     *
     */
    public function equals($ostore)
    {
        if( count($ostore->o) != count($this->o) )
        {
            //print "Not same count '".count($ostore->o)."':'".count($this->o)."'\n";
            return false;
        }
        //print "passed\n";
        foreach($this->o as $o)
        {
            if( ! in_array($o, $ostore->o, true) )
                return false;
        }
        return true;
    }



    public function equals_fasterHash( $other )
    {
        $thisHash = $this->getFastHashComp();
        $otherHash = $other->getFastHashComp();

        if( $thisHash == $otherHash )
        {
            if( $this->equals($other) )
                return true;
        }

        return false;
    }


    public function generateFastHashComp($force=false )
    {
        if( isset($this->fasthashcomp) && $this->fasthashcomp !== null && !$force )
            return;

        $class = get_class($this);
        $this->fasthashcomp = $class;

        $tmpa = $this->o;

        usort($tmpa, "__CmpObjName");

        foreach( $tmpa as $o )
        {
            $this->fasthashcomp .= '.*/'.$o->name();
        }

        $this->fasthashcomp = md5($this->fasthashcomp,true);

    }

    public function getFastHashComp()
    {
        if( !isset($this->fasthashcomp) || $this->fasthashcomp === null )
            $this->generateFastHashComp();

        return $this->fasthashcomp;
    }




    protected function has( $obj, $caseSensitive = true)
    {
        if( is_string($obj) )
        {
            if( !$caseSensitive )
                $obj = strtolower($obj);

            foreach($this->o as $o)
            {
                if( !$caseSensitive )
                {
                    if( $obj == strtolower($o->name()) )
                    {
                        return true;
                    }
                }
                else
                {
                    if( $obj == $o->name() )
                        return true;
                }
            }
            return false;
        }

        foreach( $this->o as $o )
        {
            if( $o === $obj )
                return true;
        }

        return false;

    }

    /**
     * @param string $regex
     * @return bool
     */
    protected function hasObjectRegex($regex)
    {
        foreach( $this->o as $o )
        {
            $matching = preg_match($regex, $o->name());
            if( $matching === FALSE )
                derr("regular expression error on '$regex'");
            if( $matching === 1 )
                return true;
        }
        return false;
    }


    /**
     *
     *
     */
    public function display($indentSpace = 0)
    {
        $indent = '';

        for( $i=0; $i<$indentSpace; $i++ )
        {
            $indent .= ' ';
        }

        $c = count($this->o);

        echo "$indent";
        print "Displaying the $c object(s) in ".$this->toString()."\n";

        foreach( $this->o as $o)
        {
            print $indent.$o->name()."\n";
        }
    }

    public function toString_inline()
    {
        return PH::list_to_string($this->o);
    }


    public function referencedObjectRenamed($h)
    {
        if( in_array($h,$this->o,true) )
        {
            $this->fasthashcomp = null;
            $this->rewriteXML();
        }
    }

    public function replaceReferencedObject($old, $new)
    {
        if( $old === $new )
            return false;

        $pos = array_search($old, $this->o, TRUE);

        // this object was not found so we exit and return false
        if( $pos === FALSE )
            return false;

        // remove $old from the list and unreference it
        unset($this->o[$pos]);
        $old->removeReference($this);

        // is $new already in the list ? if not then we insert it
        if( $new !== null && array_search($new, $this->o, TRUE) === FALSE )
        {
            $this->o[] = $new;
            $new->addReference($this);
        }

        // let's update XML code
        $this->rewriteXML();

        return true;
    }

    public function API_replaceReferencedObject($old, $new)
    {
        $ret = $this->replaceReferencedObject($old, $new);

        if($ret)
        {
            $this->API_sync();
        }

        return $ret;
    }

    /**
     *
     * @ignore
     **/
    protected function add($Obj)
    {
        if( !in_array($Obj,$this->o,true) )
        {
            if( isset($this->fasthashcomp) )
                unset($this->fasthashcomp);

            $this->o[] = $Obj;

            $Obj->addReference($this);

            return true;
        }

        return false;
    }

    protected function removeAll()
    {
        if( isset($this->fasthashcomp) )
            unset($this->fasthashcomp);

        foreach( $this->o as $o)
        {
            $o->removeReference($this);
        }

        $this->o = Array();

    }

    protected function remove($Obj)
    {
        if( isset($this->fasthashcomp) )
            unset($this->fasthashcomp);

        $pos = array_search($Obj,$this->o,true);
        if( $pos !== FALSE )
        {
            unset($this->o[$pos]);

            $Obj->removeReference($this);

            return true;
        }

        return false;
    }

    /**
     * Returns an array with all objects in store
     * @return array
     */
    public function getAll()
    {
        return $this->o;
    }

    public function __destruct()
    {
        if( PH::$ignoreDestructors )
            return;

        if( $this->o === null )
            return;

        // remove this object from the referencers list
        foreach($this->o as $o)
        {
            $o->removeReference($this);
        }

        $this->o = null;
        $this->owner = null;
    }

    /**
     * @param int $position
     * @throws Exception
     */
    public function getItemAtPosition($position)
    {
        if( $position < 0 )
            derr("cannot request an item with negative position ($position)");

        if( $position > count($this->o)  )
            derr("requesting item position #$position but this container has only ".count($this->o)."objects");

        return $this->o[array_keys($this->o)[$position]];

    }



    /*public function rewriteXML()
    {
        if( $this->centralStore )
        {
            clearA($this->xmlroot['children']);
        }

    }*/


    public function &getMembersDiff( $otherObject)
    {
        $result = Array('minus' => Array(), 'plus' => Array() );

        $localObjects = $this->o;
        $otherObjects = $otherObject->o;

        usort($localObjects, '__CmpObjName');
        usort($otherObjects, '__CmpObjName');

        $diff = array_udiff($otherObjects, $localObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach($diff as $d )
            {
                $result['minus'][] = $d;
            }

        $diff = array_udiff($localObjects, $otherObjects, '__CmpObjName');
        if( count($diff) != 0 )
            foreach($diff as $d )
            {
                $result['plus'][] = $d;
            }

        return $result;
    }

    public function displayMembersDiff( $otherObject, $indent=0, $toString = false)
    {
        $retString = '';

        $indent = str_pad(' ', $indent);


        $retString .= $indent."Diff for between ".$this->toString()." vs ".$otherObject->toString()."\n";

        $diff = $this->getMembersDiff($otherObject);

        if( count($diff['minus']) != 0 )
            foreach($diff['minus'] as $d )
            {
                /** @var Address|AddressGroup $d */
                $retString .= $indent." - {$d->name()}\n";
            }

        if( count($diff['plus']) != 0 )
            foreach($diff['plus'] as $d )
            {
                $retString .= $indent." + {$d->name()}\n";
            }

        if( $toString )
            return $retString;

        print $retString;
    }

    public function name()
    {
        return $this->name;
    }


}

