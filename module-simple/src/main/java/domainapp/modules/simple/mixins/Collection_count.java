package domainapp.modules.simple.mixins;

import java.util.Collection;

import org.apache.isis.applib.annotation.Property;

@Property
public abstract class Collection_count {
	
	private final Collection<?> collection;
	public Collection_count(Collection<?> collection) {
		super();
		this.collection = collection;
	}
	
	public int prop() {
		return collection.size();
	}

}
