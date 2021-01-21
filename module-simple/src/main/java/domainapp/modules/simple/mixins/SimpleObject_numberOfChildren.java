package domainapp.modules.simple.mixins;

import org.apache.isis.applib.annotation.Property;

import domainapp.modules.simple.dom.so.SimpleObject;

/*
 * ISIS-1628: the @Property mixin annotation of the abstract super class is ignored and
 * needs to be duplicated on the concrete sub class.
 * 
 * To replicate the problem remove this annotation and see how the contribution disappears from the UI.
 */
@Property
public class SimpleObject_numberOfChildren extends Collection_count {

	public SimpleObject_numberOfChildren(SimpleObject simpleObject) {
		super(simpleObject.getChildren());
	}

	/*
	 * ISIS-1628: the prop() method of the abstract super class needs to
	 * be overridden in the concrete sub class.
	 * 
	 * To replicate the problem remove this method and see how the contribution disappears from the UI.
	 */
	@Override
	public int prop() {
		return super.prop();
	}	
}
