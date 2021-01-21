package domainapp.modules.simple.dom.co;

import java.util.Comparator;

import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.IdentityType;
import javax.jdo.annotations.VersionStrategy;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.apache.isis.applib.annotation.DomainObject;
import org.apache.isis.applib.annotation.DomainObjectLayout;
import org.apache.isis.applib.annotation.Property;
import org.apache.isis.applib.annotation.PropertyLayout;
import org.apache.isis.applib.annotation.Where;
import org.apache.isis.applib.jaxb.PersistentEntityAdapter;

import domainapp.modules.simple.dom.so.SimpleObject;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@javax.jdo.annotations.PersistenceCapable(identityType=IdentityType.DATASTORE, schema = "simple")
@javax.jdo.annotations.DatastoreIdentity(strategy=IdGeneratorStrategy.IDENTITY, column="id")
@javax.jdo.annotations.Version(strategy= VersionStrategy.DATE_TIME, column="version")
@javax.jdo.annotations.Unique(name="SimpleChildObject_name_UNQ", members = {"simpleObject", "name"})
@DomainObject()
@DomainObjectLayout()
@XmlJavaTypeAdapter(PersistentEntityAdapter.class)
@ToString(onlyExplicitlyIncluded = true)
public class SimpleChildObject implements Comparable<SimpleChildObject> {

	@PropertyLayout(hidden = Where.PARENTED_TABLES)
	@Getter @Setter
	private SimpleObject simpleObject;
	
	@Getter @Setter
	private String name;
	
	private final static Comparator<SimpleChildObject> comparator =
            Comparator.comparing(SimpleChildObject::getName);

    @Override
    public int compareTo(final SimpleChildObject other) {
        return comparator.compare(this, other);
    }
	
}
