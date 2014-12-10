<?php
/**
 * Created by PhpStorm.
 * User: cpainchaud
 * Date: 10/11/2014
 * Time: 22:52
 */

class ObjRuleContainer
{
    use PathableName;


    public $owner = null;
    public $name = '';

    public $o = null;
    protected $classn=null;

    public $fasthashcomp = null;


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
        if( is_null($this->fasthashcomp) )
        {
            $this->generateFastHashComp();
        }
        if( is_null($other->fasthashcomp) )
        {
            $other->generateFastHashComp();
        }

        if( $this->fasthashcomp == $other->fasthashcomp  )
        {
            if( $this->equals($other) )
                return true;
        }

        return false;
    }


    public function generateFastHashComp($force=false )
    {
        if( !is_null($this->fasthashcomp) && !$force )
            return;

        $class = get_class($this);
        if( $class == 'AppStore' )
        {
            $fasthashcomp = $class;
        }
        else
            $fasthashcomp = 'ObjStore';

        $tmpa = $this->o;

        usort($tmpa, "__CmpObjName");

        foreach( $tmpa as $o )
        {
            $fasthashcomp .= '.*/'.$o->name();
        }

        $this->fasthashcomp = md5($fasthashcomp,true);
        unset($fasthashcomp);

    }

    public function getFastHashComp()
    {
        $this->generateFastHashComp( );
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
     *
     *
     */
    public function display($indent = 0)
    {
        $indent = '';

        for( $i=0; $i<$indent; $i++ )
        {
            $indent .= ' ';
        }

        $c = count($this->o);
        $k = array_keys($this->o);

        echo "$indent";
        print "Displaying the $c ".$this->classn."(s) in ".$this->toString()."\n";

        for( $i=0; $i<$c ;$i++)
        {
            print $indent.$this->o[$k[$i]]->name."\n";
        }
    }

    public function &toString_inline()
    {
        return PH::list_to_string($this->o);
    }


    public function hostChanged($h)
    {
        $fasthashcomp = null;

        if( in_array($h,$this->o) )
        {
            $this->rewriteXML();
        }
    }

    public function replaceHostObject($old, $new)
    {

        $pos = array_search($old, $this->o, TRUE);

        // this object was not found so we exit and return false
        if( $pos === FALSE )
            return false;

        // remove $old from the list and unreference it
        unset($this->o[$pos]);
        $old->unrefInRule($this);

        // is $new already in the list ? if not then we insert it
        if( $new !== null && array_search($new, $this->o, TRUE) === FALSE )
        {
            $this->o[] = $new;
            $new->refInRule($this);
        }

        // let's update XML code
        $this->rewriteXML();

        return true;

    }

    /**
     *
     * @ignore
     **/
    protected function add($Obj)
    {
        if( !in_array($Obj,$this->o,true) )
        {
            $fasthashcomp = null;

            $this->o[] = $Obj;

            $Obj->refInRule($this);

            return true;
        }

        return false;
    }

    protected function removeAll()
    {
        $fasthashcomp = null;

        foreach( $this->o as $o)
        {
            $o->unrefInRule($this);
        }

        $this->o = Array();

    }

    protected function remove($Obj)
    {
        $fasthashcomp = null;

        $pos = array_search($Obj,$this->o,true);
        if( $pos !== FALSE )
        {
            unset($this->o[$pos]);

            $Obj->unrefInRule($this);

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



    /*public function rewriteXML()
    {
        if( $this->centralStore )
        {
            clearA($this->xmlroot['children']);
        }

    }*/



}

